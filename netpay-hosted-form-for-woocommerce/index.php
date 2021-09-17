<?php
/*
  Plugin Name: NetPay Hosted Payment Gateway For WooCommerce
  Description: Extends WooCommerce to Process Payments with NetPay's Hosted Payment Gateway Method .
  Version: 1.0
  Plugin URI: http://netpay.co.uk
  Author: Avinash Kumar
  Author URI: http://www.netpay.co.uk/
  License: Under TBI
  Note: Tested upto wordpress latest version WP5.8 and tested upto woocommerce version 5.6.0
 */
 
add_action('plugins_loaded', 'woocommerce_tbi_netpay_init', 0);

function woocommerce_tbi_netpay_init()
{

    if (!class_exists('WC_Payment_Gateway'))
        return;

    /**
     * Localisation
     */
    load_plugin_textdomain('wc-tbi-netpay', false, dirname(plugin_basename(__FILE__)) . '/languages');

    /**
     * NetPay Payment Gateway class
     */
    class WC_Tbi_Netpay extends WC_Payment_Gateway {

        protected $msg = array();

        public function __construct()
        {

            $this->method = esc_html('AES-128-CBC', 'tbi'); // Encryption method, IT SHOULD NOT BE CHANGED

            $this->id = esc_html('netpay', 'tbi');
            $this->method_title = __('NetPay Hosted Payment Gateway Method', 'tbi');
            $this->icon = WP_PLUGIN_URL . "/" . plugin_basename(dirname(__FILE__)) . '/images/logo.gif';
            $this->has_fields = false;

            $this->init_form_fields();
            $this->init_settings();

            //Setting allows to test plugin without making real payment, notifies clearly to merchant that order was paid using Test Mode
            if ($this->settings['working_mode'] == 'test') {
                $this->title = $this->settings['title'] . " - <b>".esc_html('Test Mode', 'tbi')."</b>";
            }
            else {
                $this->title = $this->settings['title'];
            }

            $this->description = $this->settings['description'];
            $this->merchant_id = $this->settings['merchant_id'];
            $this->netpay_username = $this->settings['netpay_username'];
            $this->netpay_password = $this->settings['netpay_password'];
            $this->enc_key = $this->settings['netpay_encryption_key'];
            $this->enc_iv = $this->settings['netpay_encryption_iv'];
            //Allows for different Checkout Templates to be used
            $this->checkout_template = $this->settings['checkout_template'];
            //Sets Live or Test mode for payments
            $this->mode = $this->settings['working_mode'];
            //Allows for merchant to receive response directly from NetPay servers instead of with client coming back from hosted page
            $this->backend_response = $this->settings['backend_response'];
            //Cron is not able to verify peer if CA bundle is not set, we allow plugin to work if merchant cannot set it
            $this->verify_peer = $this->settings['verify_peer'];
            //Live and Test URL for Server Post
            $this->liveurl = 'https://hosted.revolution.netpay.co.uk/v1/gateway/create_payment_link';
            $this->testurl = 'https://hostedtest.revolution.netpay.co.uk/v1/gateway/create_payment_link';
            $this->msg['message'] = "";
            $this->msg['class'] = "";

            add_action('init', array(&$this, 'check_netpay_response'));
            add_action('woocommerce_api_wc_tbi_netpay', array($this, 'check_netpay_response'));

            if (version_compare(WOOCOMMERCE_VERSION, '5.0.0', '>=')) {
                add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'process_admin_options'));
            }
            else {
                add_action('woocommerce_update_options_payment_gateways', array(&$this, 'process_admin_options'));
            }

            add_action('woocommerce_receipt_netpay', array(&$this, 'receipt_page'));
            add_action('woocommerce_thankyou_netpay', array(&$this, 'thankyou_page'));
        }

        /**
         * Shows settings fields in admin panel, initializes default values and assigns descriptions
         */
        function init_form_fields()
        {
            $this->form_fields = array(
                'enabled' => array(
                    'title' => __('Enable/Disable', 'tbi'),
                    'type' => 'checkbox',
                    'label' => __('Enable NetPay Hosted Form Method Payment Module.', 'tbi'),
                    'default' => 'no'),
                'title' => array(
                    'title' => __('Title:', 'tbi'),
                    'type' => 'text',
                    'description' => __('This controls the title which the user sees during checkout.', 'tbi'),
                    'default' => __('NetPay', 'tbi')),
                'description' => array(
                    'title' => __('Description:', 'tbi'),
                    'type' => 'textarea',
                    'description' => __('This controls the description which the user sees during checkout.', 'tbi'),
                    'default' => __('Pay securely by Credit or Debit Card through NetPay Secure Servers.', 'tbi')),
                'merchant_id' => array(
                    'title' => __('Merchant ID', 'tbi'),
                    'type' => 'text',
                    'description' => __('This is your merchant account ID')),
                'netpay_username' => array(
                    'title' => __('Username', 'tbi'),
                    'type' => 'text',
                    'description' => __('This is your integration NetPay API Username to authenticate your request', 'tbi')),
                'netpay_password' => array(
                    'title' => __('Password', 'tbi'),
                    'type' => 'text',
                    'description' => __('This is your integration NetPay API Password to authenticate your request', 'tbi')),
                'netpay_encryption_key' => array(
                    'title' => __('Encryption Key', 'tbi'),
                    'type' => 'text',
                    'description' => __('This is your Encryption Key to encrypt your form data before posting to NetPay’s Server', 'tbi')),
                'netpay_encryption_iv' => array(
                    'title' => __('Encryption IV', 'tbi'),
                    'type' => 'text',
                    'description' => __('This is your Encryption Initialising Vector (IV). It is used with your Encryption Key to encrypt the form data', 'tbi')),
                'checkout_template' => array(
                    'title' => __('Checkout Style'),
                    'type' => 'select',
                    'options' => array('standard' => 'Standard', 'swift' => 'Swift'),
                    'description' => __("Set style of checkout that user will see when paying for order", 'tbi'),
                    'default' => 'standard'),
                'working_mode' => array(
                    'title' => __('Payment Mode'),
                    'type' => 'select',
                    'options' => array('live' => 'Live Mode', 'test' => 'Test/Sandbox Mode'),
                    'description' => "Live/Test Mode",
                    'default' => 'live'),
                'backend_response' => array(
                    'title' => __('Allow Backend Response'),
                    'type' => 'select',
                    'options' => array('yes' => 'Yes', 'no' => 'No'),
                    'description' => "Allow NetPay to send backend response if the user close browser before redirecting back to response URL",
                    'default' => 'yes'),
                'verify_peer' => array(
                    'title' => __('Verify secure connection to NetPay server'),
                    'type' => 'select',
                    'options' => array('no' => 'No', 'yes' => 'Yes'),
                    'description' => __("Set if connection over HTTPS to NetPay server should validate NetPay server certificate (Requires CA bundle to be available for cURL on server).", 'tbi'),
                    'default' => 'no')
            );
        }

        /**
         * Admin Panel Options
         * - Options for bits like 'title' and availability on a country-by-country basis
         * Does not allow to set options for plugin unless cURL is enabled on server since
         * client post method is deprecated
         */
        public function admin_options()
        {
			$string = get_woocommerce_currency();
			$gbp = esc_html('GBP', 'tbi');
			if($string != $gbp){
				echo '<h2>';
					esc_html_e('This payment gateway is works with default currency United Kingdom (£), So please change the default currencies to United Kingdom (£) ie GBP from General->General options section to make this gateway properly works', 'tbi');
				echo '</h2>';
			}
			else{
				echo '<h3>';
					esc_html_e('NetPay Hosted Form Method Payment Configuration', 'tbi');
				echo '</h3>';
				echo '<p>'; 
					esc_html_e('NetPay is most popular payment gateway for online payment processing','tbi');
				echo '</p>';
				echo '<table class="form-table">';
					$this->generate_settings_html();
				echo '</table>';
			}
        }

        /**
         * Returns url based on Live/Test mode
         */
        public function form_submit_url()
        {
            if ($this->mode == 'live')
                return $this->liveurl;
            else
                return $this->testurl;
        }

        /**
         * Returns Operation Mode number based on setting
         */
        public function operation_mode()
        {
            if ($this->mode == 'live')
                return '1';
            else
                return '2';
        }

        /**
         * ADD PKCS5 PADDING
         */
        public function add_pkcs5_padding($text, $blocksize)
        {
            $pad = $blocksize - (strlen($text) % $blocksize);
            return $text . str_repeat(chr($pad), $pad);
        }

		/* 	OPENSSL ENCRYPTION
		 * 	MODE CBC
		 */		
		/***************** Encrypted Function Start*******************/
		public function mcrypt_encrypt_cbc($input, $key, $iv) {
			$size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
			$input = $this->add_pkcs5_padding($input, $size);
			$td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');

			mcrypt_generic_init($td, pack('H*', $key), pack('H*', $iv));
			$data = mcrypt_generic($td, $input);
			mcrypt_generic_deinit($td);
			mcrypt_module_close($td);
			$data = bin2hex($data);

			return $data;
		}

		/* 	MCRYPT DECRYPTION
		 * 	MODE CBC
		 */

		public function mcrypt_decrypt_cbc($input, $key, $iv) {
			$decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, pack('H*', $key), pack('H*', $input), MCRYPT_MODE_CBC, pack('H*', $iv));

			return $this->remove_pkcs5_padding($decrypted);
		}

		/* 	OPENSSL ENCRYPTION
		 * 	MODE CBC
		 */

		public function openssl_encrypt_cbc($input, $key, $iv, $method) {
			$encrypted = openssl_encrypt($input, $method, pack('H*', $key), TRUE, pack('H*', $iv));

			$encrypted_hex = bin2hex($encrypted);

			return $encrypted_hex;
		}

		/* 	OPENSSL DECRYPTION
		 * 	MODE CBC
		 */

		public function openssl_decrypt_cbc($input, $key, $iv, $method) {
			$decrypted = openssl_decrypt(pack('H*', $input), $method, pack('H*', $key), true, pack('H*', $iv));

			return $decrypted;
		}

		/*
		 * 	REMOVE PKCS5 PADDING
		 */

		private function remove_pkcs5_padding($decrypted) {
			$dec_s = strlen($decrypted);
			$padding = ord($decrypted[$dec_s - 1]);
			$decrypted = substr($decrypted, 0, -$padding);

			return $decrypted;
		}

		/*
		 * 	Add timestamp to transaction id
		 */

		public function create_unique_transaction_id($transaction_id) {
			$time = time();
			$time_1 = substr($time, 0, floor(strlen($time) / 2));
			$time_2 = substr($time, floor(strlen($time) / 2));
			$rand = '';
			$seed = str_split('abcdefghijklmnopqrstuvwxyz'
					. 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
			foreach (array_rand($seed, 3) as $k)
				$rand .= $seed[$k];

			$unique_trans_id = strtolower($transaction_id) . $time_1 . $rand . $time_2;
			return hash('adler32', $unique_trans_id) . hash('crc32', $unique_trans_id);
		}

		/*
		 * 	Create token with combination of merchant_id, timestamp and transaction_id
		 */

		public function create_unique_session_token($merchant_id, $transaction_id) {
			$time = time();
			$time_1 = substr($time, 0, floor(strlen($time) / 2));
			$time_2 = substr($time, floor(strlen($time) / 2));
			$rand = '';
			$seed = str_split('abcdefghijklmnopqrstuvwxyz'
					. 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
			foreach (array_rand($seed, 3) as $k)
				$rand .= $seed[$k];

			return substr(strtolower($merchant_id) . $time_1 . $rand . $time_2 . strtolower($transaction_id), 0, 25);
		}

		public function get_url($url) {
			if (isset($_SERVER['HTTPS'])) {
				$protocol = ($_SERVER['HTTPS'] && $_SERVER['HTTPS'] != "off") ? "https" : "http";
			} else {
				$protocol = 'http';
			}
			return $protocol . "://" . $_SERVER['HTTP_HOST'] . $url;
		}
		
		public function get_json_data($response)
		{
			$data = json_decode($response, TRUE);

			return $data;
		}

		public function get_xml_data($response)
		{
			$xml = simplexml_load_string($response, 'SimpleXMLElement', LIBXML_NOCDATA);
			$data = json_decode(json_encode($xml), TRUE);

			return $data;
		}

		public function get_str_data($response)
		{
			$data = self::parse_response_url($response);

			return $data;
		}
		
		// Parse response string
		public function parse_response_url($response)
		{
			preg_match_all('/\{([^}]*)\}/', $response, $matches);

			$parsed_url = array();
			foreach ($matches[1] as $match) {
				list($key, $value) = explode('|', $match);
				$parsed_url[$key] = $value;
			}

			return $parsed_url;
		}
		
		/***************** Encrypted Function End*******************/
		
	
        /**
         * There are no payment fields for NetPay Hosted payment method,
         * but we want to show the description if one is set
         */
        function payment_fields()
        {
            if ($this->description)
                echo wpautop(wptexturize($this->description)) . "<br>";
        }

        /**
         * We do nothing on Thank You page
         */
        public function thankyou_page($order_id)
        {
          
        }

        /**
         * Receipt Page - sends query for redirect URL to NetPay and redirects
         * or shows error if something went wrong
         */
        function receipt_page($order)
        {
            echo $this->generate_netpay_form($order);
        }

        /**
         * Process the payment and return the result
         */
        function process_payment($order_id)
        {
            $order = new WC_Order($order_id);
            if (version_compare(WOOCOMMERCE_VERSION, '2.1', '<')) {
                return array('result' => 'success',
                    'redirect' => add_query_arg('order', $order->id, add_query_arg('key', $order->order_key, get_permalink(get_option('woocommerce_pay_page_id'))))
                );
            }
            else {
                return array('result' => 'success',
                    'redirect' => $order->get_checkout_payment_url(true)
                );
            }
        }

        /**
         * Check for valid NetPay server callback to validate the transaction response.
         */
        function check_netpay_response()
        {
            //Condition to check if backend response is enabled from admin panel
            if ($this->backend_response == 'yes') {
                if (isset($_POST['response'])) {
                    //Handle backend response received from NetPay.
                    $response = esc_attr($_POST['response']);
                    $orderId = sanitize_text_field($_GET['order_id']);
                    //Try decrypting response received
					$encryption_method = esc_html('AES-128-CBC', 'tbi');
                    $decrypted_response = $this->openssl_decrypt_cbc($response, $this->enc_key, $this->enc_iv, $encryption_method);
                    //Split response into array after decryption
                    $response_array = json_decode($decrypted_response, TRUE);
                    $order = new WC_Order($orderId);

                    global $woocommerce;

                    if (is_array($response_array) && count($response_array)) {
                        //If result of response is not empty
                        if ($response_array['result'] != '') {

                            //If result is SUCCESS
                            if ($response_array['result'] == 'SUCCESS') {
                                $this->msg['message'] = '';
                                //Don't change order if it was already set to processing
                                if ($order->status == 'processing') {

                                }
                                else {
                                    //Updating extra information in databaes corresponding to placed order.
                                    update_post_meta($orderId, 'netpay_order_id', $response_array['order_id']);
                                    update_post_meta($orderId, 'netpay_payment_status', $response_array['result']);
                                    
                                    //Validate currency
                                    if ($order->get_order_currency() != $response_array['currency']) {
                                        //Put this order on-hold for manual checking
                                        $order->update_status('on-hold', sprintf(__('Validation error: NetPay currencies do not match (NetPay response: %s).', 'woocommerce'), $response_array['currency']));
                                        exit;
                                    }

                                    //Validate amount
                                    if ($order->get_total() != $response_array['amount']) {
                                        //Put this order on-hold for manual checking
                                        $order->update_status('on-hold', sprintf(__('Validation error: NetPay amounts do not match (NetPay response: %s).', 'woocommerce'), $response_array['amount']));
                                        exit;
                                    }

                                    $order_transaction_id = get_post_meta($orderId, 'netpay_transaction_id', TRUE);

                                    //Validate transaction_id
                                    if ($order_transaction_id != $response_array['transaction_id']) {
                                        //Put this order on-hold for manual checking
                                        $order->update_status('on-hold', sprintf(__('Validation error: NetPay transaction id do not match (NetPay response: %s).', 'woocommerce'), $response_array['transaction_id']));
                                        exit;
                                    }

                                    //If it passed all checks set Payment as completed
                                    $order->payment_complete();
                                    $order->add_order_note(esc_html('NetPay payment successful<br/>NetPay Transaction ID: ' . $response_array['transaction_id'] . '<br/>NetPay Order ID: ' . $response_array['order_id'], 'tbi'));
                                    $woocommerce->cart->empty_cart();
                                    $order->add_order_note(esc_html($this->msg['message'], 'tbi'));
                                }
                            }
                            else {
                                //Updating extra information in databaes corresponding to placed order.
                                update_post_meta($orderId, 'netpay_order_id', $response_array['order_id']);
                                update_post_meta($orderId, 'netpay_payment_status', $response_array['result']);

                                $order->update_status('failed');
                                $order->add_order_note("Error Code: " . $response_array['code'] . " - " . $response_array['explanation']);
                            }
                        }
                        else {
                            $order->add_order_note(esc_html('Payment response received but it was in wrong format.', 'tbi'));
                        }
                    }
                    else {
                        $order->add_order_note(esc_html('Payment response received but it was in wrong format.', 'tbi'));
                    }
                }
                else {
                    //Handle backend response received from NetPay.
                    $response = esc_attr($_GET['response']);
                    $orderId = sanitize_text_field($_GET['order_id']);
                    //Try decrypting response received
					$encryption_method = esc_html('AES-128-CBC', 'tbi');
                    $decrypted_response = $this->openssl_decrypt_cbc($response, $this->enc_key, $this->enc_iv, $encryption_method);
                    //Split response into array after decryption
                    $response_array = json_decode($decrypted_response, TRUE);

                    $order = new WC_Order($orderId);

                    global $woocommerce;

                    if (is_array($response_array) && count($response_array)) {
                        $redirect_url = '';
                        $this->msg['class'] = esc_html('error', 'tbi');
                        $this->msg['message'] = esc_html('set error msg', 'tbi'); //$this->failed_message;

                        //If it was set as backend response and it is frontend success just clear cart
                        if ($response_array['result'] === 'SUCCESS') {
                            $this->msg['message'] = ''; // set message
                            $this->msg['class'] = esc_html('success', 'tbi');

                            if ($order->status == 'processing') {
                                
                            }
                            else {
                                $woocommerce->cart->empty_cart();
                            }
                        }
                        //If it was set as backend response and it is frontend payment fail we need to set order status as failed here for woocommerce to show error on next page
                        else {
                            $order->update_status('failed');
                            $this->msg['message'] = esc_html('There was a problem with the payment.', 'tbi');
                        }

                        if (version_compare(WOOCOMMERCE_VERSION, '2.1', '<')) {
                            $redirect_url = add_query_arg('order', $order->id, add_query_arg('key', $order->order_key, get_permalink(get_option('woocommerce_thanks_page_id'))));
                        }
                        else {
                            $redirect_url = add_query_arg('key', $order->order_key, $this->get_return_url($order));
                        }

                        if ($this->msg['class'] === 'error') {
                            $redirect_url = add_query_arg('msg', $this->msg['message'], $redirect_url);
                        }

                        $this->web_redirect($redirect_url);
                        exit;
                    }
                    else {
                        $order->update_status('failed');
                        if (version_compare(WOOCOMMERCE_VERSION, '2.1', '<')) {
                            $redirect_url = add_query_arg('order', $order->id, add_query_arg('key', $order->order_key, get_permalink(get_option('woocommerce_thanks_page_id'))));
                        }
                        else {
                            $redirect_url = add_query_arg('key', $order->order_key, $this->get_return_url($order));
                        }
                        $this->web_redirect($redirect_url . '?msg=Unknown_error_occured');
                        exit;
                    }
                } // end of else if request after completion
            }
            else {
                $response = esc_attr($_GET['response']);
                $orderId = sanitize_text_field($_GET['order_id']);
				$encryption_method = esc_html('AES-128-CBC','tbi');
                $decrypted_response = $this->openssl_decrypt_cbc($response, $this->enc_key, $this->enc_iv, $encryption_method);
                $response_array = json_decode($decrypted_response, TRUE);

                $order = new WC_Order($orderId);

                global $woocommerce;

                if (is_array($response_array) && count($response_array)) {

                    $redirect_url = '';
                    $this->msg['class'] = esc_html('error', 'tbi');
                    
                    if (version_compare(WOOCOMMERCE_VERSION, '2.1', '<')) {
                        $redirect_url = add_query_arg('order', $order->id, add_query_arg('key', $order->order_key, get_permalink(get_option('woocommerce_thanks_page_id'))));
                    }
                    else {
                        $redirect_url = add_query_arg('key', $order->order_key, $this->get_return_url($order));
                    }

                    //If result of response is not empty
                    if ($response_array['result'] != '') {
                        try {
                            //If result is SUCCESS
                            if ($response_array['result'] == 'SUCCESS') {
                                $this->msg['class'] = esc_html('success', 'tbi');
                                //Don't change order if it was already set to processing
                                if ($order->status == 'processing') {

                                }
                                else {
                                    // updating extra information in databaes corresponding to placed order.
                                    update_post_meta($orderId, 'netpay_order_id', $response_array['order_id']);
                                    update_post_meta($orderId, 'netpay_payment_status', $response_array['result']);

                                    // Validate currency
                                    if ($order->get_order_currency() != $response_array['currency']) {
                                        //Put this order on-hold for manual checking
                                        $order->update_status('on-hold', sprintf(__('Validation error: NetPay currencies do not match (NetPay response: %s).', 'woocommerce'), $response_array['currency']));
                                        $this->web_redirect($redirect_url);
                                        exit;
                                    }

                                    // Validate amount
                                    if ($order->get_total() != $response_array['amount']) {
                                        //Put this order on-hold for manual checking
                                        $order->update_status('on-hold', sprintf(__('Validation error: NetPay amounts do not match (NetPay response: %s).', 'woocommerce'), $response_array['amount']));
                                        $this->web_redirect($redirect_url);
                                        exit;
                                    }

                                    $order_transaction_id = get_post_meta($orderId, 'netpay_transaction_id', TRUE);

                                    // Validate transaction_id
                                    if ($order_transaction_id != $response_array['transaction_id']) {
                                        //Put this order on-hold for manual checking
                                        $order->update_status('on-hold', sprintf(__('Validation error: NetPay transaction id do not match (NetPay response: %s).', 'woocommerce'), $response_array['transaction_id']));
                                        $this->web_redirect($redirect_url);
                                        exit;
                                    }

                                    //If it passed all checks set Payment as completed
                                    $order->payment_complete();
                                    $order->add_order_note(esc_html('NetPay payment successful<br/>NetPay Transaction ID: ' . $response_array['transaction_id'] . '<br/>NetPay Order ID: ' . $response_array['order_id'], 'tbi'));
                                    $woocommerce->cart->empty_cart();
                                }
                            }
                            else {
                                //Updating extra information in database corresponding to placed order
                                update_post_meta($orderId, 'netpay_order_id', '');
                                update_post_meta($orderId, 'netpay_payment_status', $response_array['result'] . " : " . $response_array['explanation']);

                                $order->update_status('failed');
                                $order->add_order_note("Error Code: " . $response_array['code'] . " - " . $response_array['explanation']);
                            }
                        }
                        catch (Exception $e) {
                            $msg = esc_html("Error", "tbi");
                        }
                    }
                    else {
                        $order->add_order_note(esc_html('Payment response received but it was in wrong format.', 'tbi'));
                    }
                    $this->web_redirect($redirect_url);
                    exit;
                }
                else {
                    if (version_compare(WOOCOMMERCE_VERSION, '2.1', '<')) {
                        $redirect_url = add_query_arg('order', $order->id, add_query_arg('key', $order->order_key, get_permalink(get_option('woocommerce_thanks_page_id'))));
                    }
                    else {
                        $redirect_url = add_query_arg('key', $order->order_key, $this->get_return_url($order));
                    }
                    $order->add_order_note(esc_html('Payment response received but it was in wrong format.', 'tbi'));
                    $this->web_redirect($redirect_url . '?msg=Unknown_error_occured');
                    exit;
                }
            }
        }

        /**
         * Redirect website using JavaScript
         */
        public function web_redirect($url)
        {
            echo "<html><head><script language=\"javascript\">
				   <!--
				   window.location=\"{$url}\";
				   //-->
				   </script>
				   </head><body><noscript><meta http-equiv=\"refresh\" content=\"0;url={$url}\"></noscript></body></html>";
        }

        /**
         * Generate NetPay Server Post query and redirect to Hosted payment page
         * or return error information
         */
        public function generate_netpay_form($order_id)
        {
            global $woocommerce;
			
            $order = new WC_Order($order_id);
			$orders = wc_get_order( $order_id );
			$user_id = get_post_meta( $order_id, '_customer_user', true );
			// Get an instance of the WC_Customer Object from the user ID
			$customer = new WC_Customer( $user_id );

			$username     = $customer->get_username(); // Get username
			$user_email   = $customer->get_email(); // Get account email
			$first_name   = $customer->get_first_name();
			$last_name    = $customer->get_last_name();
			$display_name = $customer->get_display_name();

			// Customer billing information details (from account)
			$billing_first_name = $orders->get_billing_first_name();
			$billing_last_name  = $orders->get_billing_last_name();
			$billing_company    = $orders->get_billing_company();
			$billing_address_1  = $orders->get_billing_address_1();
			$billing_address_2  = $orders->get_billing_address_2();
			$billing_city       = $orders->get_billing_city();
			$billing_state      = $orders->get_billing_state();
			$billing_postcode   = $orders->get_billing_postcode();
			$billing_country    = $orders->get_billing_country();
			$billing_email    = $orders->get_billing_email();
			$billing_phone    = $orders->get_billing_phone();

			// Customer shipping information details (from account)
			$shipping_first_name = $orders->get_shipping_first_name();
			$shipping_last_name  = $orders->get_shipping_last_name();
			$shipping_company    = $orders->get_shipping_company();
			$shipping_address_1  = $orders->get_shipping_address_1();
			$shipping_address_2  = $orders->get_shipping_address_2();
			$shipping_city       = $orders->get_shipping_city();
			$shipping_state      = $orders->get_shipping_state(); 
			$shipping_postcode   = $orders->get_shipping_postcode();
			$shipping_country    = $orders->get_shipping_country();

			$shipping_method = $orders->get_shipping_method();

            if (version_compare(WOOCOMMERCE_VERSION, '2.1', '<')) {
                $redirect_url = (get_option('woocommerce_thanks_page_id') != '' ) ? get_permalink(get_option('woocommerce_thanks_page_id')) : get_site_url() . '/';
            }
            else {
                $redirect_url = $order->get_checkout_payment_url($on_checkout = false);
            }

            //Prepare response URL
            $relay_url = add_query_arg(array('wc-api' => get_class($this), 'order_id' => $order_id), $redirect_url);

            $order_description = esc_html("New order with order id " . $order_id . " and amount " . get_woocommerce_currency() . " " . $order->get_total() . " has been placed.", 'tbi');
			$encryption_method = esc_html('AES-128-CBC', 'tbi');
            $respUrl = $this->openssl_encrypt_cbc($relay_url, $this->enc_key, $this->enc_iv, $this->method);

            $session_token = $this->create_unique_session_token($this->merchant_id, $order_id);
            $transaction_id = $this->create_unique_transaction_id($order_id);
			
            //Set standard hosted form variables based on settings
            $netpay_args = array(
                'merchant_id' => $this->merchant_id,
                'username' => $this->openssl_encrypt_cbc($this->netpay_username, $this->enc_key, $this->enc_iv, $this->method),
                'password' => $this->openssl_encrypt_cbc($this->netpay_password, $this->enc_key, $this->enc_iv, $this->method),
				'session_token' => $this->openssl_encrypt_cbc($session_token, $this->enc_key, $this->enc_iv, $this->method),
                'operation_mode' => $this->openssl_encrypt_cbc($this->operation_mode(), $this->enc_key, $this->enc_iv, $this->method),                
                'description' => $this->openssl_encrypt_cbc(trim(substr($order_description, 0, 100)), $this->enc_key, $this->enc_iv, $this->method),
                'amount' => $this->openssl_encrypt_cbc($order->get_total(), $this->enc_key, $this->enc_iv, $this->method),
                'currency' => $this->openssl_encrypt_cbc(get_woocommerce_currency(), $this->enc_key, $this->enc_iv, $this->method),
                'transaction_id' => $this->openssl_encrypt_cbc($transaction_id, $this->enc_key, $this->enc_iv, $this->method),
                'response_url' => $respUrl,
                'response_format' => $this->openssl_encrypt_cbc('JSON', $this->enc_key, $this->enc_iv, $this->method),
                'checksum' => $this->openssl_encrypt_cbc(sha1($session_token . $order->get_total() . get_woocommerce_currency() . $transaction_id), $this->enc_key, $this->enc_iv, $this->method),
            );
            
            //Set checkout template to SWIFT if it was selected
            if($this->checkout_template == 'swift') {
                $netpay_args['checkout_template'] = $this->openssl_encrypt_cbc('SWIFT', $this->enc_key, $this->enc_iv, $this->method);
            }

            //Set for Hosted Portal to return backend response if that setting was selected
            if($this->backend_response == 'yes') {
                $netpay_args['backend_response'] = $this->openssl_encrypt_cbc('1', $this->enc_key, $this->enc_iv, $encryption_method);
            }

            //Prepare Cart item string
            $cartItemString = '';
			
			$items = $order->get_items();
            foreach ($items as $item_id => $item) {
			    $product = $item->get_product();
                //Get the product ID
                $item_id = $item->get_product_id();

                //Get the Item Name
                $item_name = $item->get_name();
                //Strip any characters that should not be there
                $item_name = strip_tags($item_name);
                $item_name = preg_replace('/[\x00-\x1F\x80-\xFF\|\}\{]/', '', $item_name);
                //Make sure that the number of characters are no more than the API expects
                if (strlen($item_name) > 97) {
                    $item_description = substr($item_name, 0, 97) . "..."; // max 100 character description can be sent
                }

                //Get the item description
                $item_description = $product->get_description();
                //Strip any characters that should not be there
                $item_description = strip_tags($item_description);
                $item_description = preg_replace('/[\x00-\x1F\x80-\xFF\|\}\{]/', '', $item_description);
                //If the tags were incorrect item description may be now be blank or it may have been blank to begin with so we will set it to item name
                if (strlen($item_description) == 0) {
                    $item_description = $item_name;
                }


                //Make sure that the number of characters are no more than the API expects
                if (strlen($item_description) > 197) {
                    $item_description = substr($item_description, 0, 197) . "..."; // max 200 character description can be sent
                }

                //Get the item quantity makeing sure we strip any unwanted characters
                $item_qty = preg_replace("/[^0-9]/", "", $item->get_quantity());

                //If quantity is not set then set to 0 but this will probably fail the transaction as well
                if (trim($item_qty) == '') {
                    $item_qty = 0;
                }

                //See if we are using sale price or regular price
                if (version_compare(WOOCOMMERCE_VERSION, '2.1', '<')) {
                    //Check if sale price is available otherwise, assign regular price
                    if (get_post_meta($item->get_product_id(), '_sale_price', true) != '') {
                        $productPrice = get_post_meta($item->get_product_id(), '_sale_price', true);
                    }
                    else {
                        $productPrice = get_post_meta($item->get_product_id(), '_regular_price', true);
                    }
                }
                else {
                    //Check if sale price is available otherwise, assign regular price
                    if ($product->get_sale_price() != '') {
                        $productPrice = $product->get_sale_price();
                    }
                    else {
                        $productPrice = $product->get_regular_price();
                    }
                }

                //See if item is taxable
                if (version_compare(WOOCOMMERCE_VERSION, '2.1', '<')) {
                    //Check if product is taxable
                    if (get_post_meta($item->get_product_id(), '_tax_status', true) != '') {
                        $item_taxable = '1';
                    }
                    else {
                        $item_taxable = '0';
                    }
                }
                else {
                    if ($item->get_tax_status()) {
                        $item_taxable = '1';
                    }
                    else {
                        $item_taxable = '0';
                    }
                }

                //If there is no price then set price to 0.00
                //Note that the API does require a value greater than zero so this will fail after proceed
                if (trim($productPrice) == '') {
                    $productPrice = "0.00";
                }

                //If price starts with a decimal place replace it with 0.
                $item_price = number_format($productPrice, 2, '.', '');
                $cartItemString .= "[{item_id|" . $item_id . "}{item_name|" . $item_name . "}{item_description|" . $item_description . "}{item_quantity|" . $item_qty . "}{item_price|" . $item_price . "}{item_taxable|" . $item_taxable . "}] ";
            }

            //Get the name of the web browser being used
            $browserName = $this->getBrowser();

            //If there is no shipping address use billing by default and strip any unwanted characters
            if (trim($order->get_formatted_shipping_address()) == '') {
                $netpay_info_args = array(
                    'bill_to_company' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_company), 0, 100))),
                    'bill_to_address' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_address_1 . ' ' . $billing_address_2), 0, 100))),
                    'bill_to_town_city' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_city), 0, 50))),
                    'bill_to_county' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_state), 0, 50))),
                    'bill_to_postcode' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_postcode), 0, 10))),
                    'bill_to_country' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($this->getValidCountryCode($billing_country)), 0, 3))),
                    'customer_email' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', strip_tags($billing_email)),
                    'customer_phone' => preg_replace('/[^0-9]/', '', strip_tags($billing_phone)),
                    'ship_to_firstname' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_first_name), 0, 50))),
                    'ship_to_lastname' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_last_name), 0, 50))),
                    'ship_to_fullname' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_first_name . ' ' . $billing_last_name), 0, 100))),
                    'ship_to_company' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_company), 0, 100))),
                    'ship_to_address' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_address_1 . ' ' . $billing_address_2), 0, 100))),
                    'ship_to_town_city' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_city), 0, 50))),
                    'ship_to_county' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_state), 0, 50))),
                    'ship_to_country' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($this->getValidCountryCode($billing_country)), 0, 3))),
                    'ship_to_postcode' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_postcode), 0, 10))),
                    'ship_to_method' => trim(substr($shipping_method , 0, 20)),
                    'customer_ip_address' => trim(substr($_SERVER['REMOTE_ADDR'], 0, 15)),
                    'customer_hostname' => trim(substr($_SERVER['HTTP_HOST'], 0, 60)),
                    'customer_browser' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($browserName['name']), 0, 60))),
                    'order_items' => $cartItemString
                );
            }
            //Otherwise use billing and shipping address supplied stripping out any unwanted characters
            else {
                $netpay_info_args = array(
                    'bill_to_company' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_company), 0, 100))),
                    'bill_to_address' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_address_1 . ' ' . $billing_address_2), 0, 100))),
                    'bill_to_town_city' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_city), 0, 50))),
                    'bill_to_county' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_state), 0, 50))),
                    'bill_to_postcode' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($billing_postcode), 0, 10))),
                    'bill_to_country' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($this->getValidCountryCode($billing_country)), 0, 3))),
                    'customer_email' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', strip_tags($billing_email)),
                    'customer_phone' => preg_replace('/[^0-9]/', '', strip_tags($billing_phone)),
                    'ship_to_firstname' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($shipping_first_name), 0, 50))),
                    'ship_to_lastname' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($shipping_last_name), 0, 50))),
                    'ship_to_fullname' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($shipping_first_name . ' ' . $shipping_last_name), 0, 100))),
                    'ship_to_company' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($shipping_company), 0, 100))),
                    'ship_to_address' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($shipping_address_1 . ' ' . $shipping_address_2), 0, 100))),
                    'ship_to_town_city' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($shipping_city), 0, 50))),
                    'ship_to_county' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($shipping_state), 0, 50))),
                    'ship_to_country' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($this->getValidCountryCode($shipping_country)), 0, 3))),
                    'ship_to_postcode' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($shipping_postcode), 0, 10))),
                    'ship_to_method' => trim(substr($shipping_method , 0, 20)),
                    'customer_ip_address' => trim(substr($_SERVER['REMOTE_ADDR'], 0, 15)),
                    'customer_hostname' => trim(substr($_SERVER['HTTP_HOST'], 0, 60)),
                    'customer_browser' => preg_replace('/[\x00-\x1F\x80-\xFF]/', '', trim(substr(strip_tags($browserName['name']), 0, 60))),
                    'order_items' => $cartItemString
                );
            }


            $netpay_args_array = array();
            //Creating merged table of fields from Basic Form
            foreach ($netpay_args as $key => $value) {
                $netpay_args_array[$key] = $value;
            }

            //Creating merged table of fields from Advanced Form
            foreach ($netpay_info_args as $key => $value) {
                if ($value != '') {
                    $enc_value = $this->openssl_encrypt_cbc($value, $this->enc_key, $this->enc_iv, $this->method);
                    $netpay_args_array[$key] = $enc_value;
                }
            }
			
            //Use Server Post URL based on selected mode
            if ($this->mode == 'test') {
                $processURI = $this->testurl;
            }
            else {
                $processURI = $this->liveurl;
            }

			$username = $netpay_args_array['username'];
			$password = $netpay_args_array['password'];
			$args = array(
					'method' => 'POST',
					'data_format' => 'body',
					'httpversion' => '1.0',
					'blocking' => true,
					'headers' => array( 
							'Authorization' => 'Basic ' . base64_encode($username . ':' . $password),
							),
					'body' => $netpay_args_array                      
				);
			$responses = wp_remote_post($processURI, $args);
			if(is_wp_error( $responses)){
				 $error_message = $responses->get_error_message();
				 return esc_html("Something went wrong: $error_message", "tbi");
			} 
			else {
				 if(!empty(wp_remote_retrieve_body($responses))){
					 $response = wp_remote_retrieve_body($responses);
				 }
				 else{
					  $error_message = $responses->get_error_message();
				      return esc_html("Something went wrong: $error_message", "tbi");
				 }
			}
			
            //If there was no error with connection
            if ($response !== FALSE) {
                //Try decrypting response
                $resp_data = $this->openssl_decrypt_cbc($response, $this->enc_key, $this->enc_iv, $this->method);
                //Decode response from JSON
                $resp_data = json_decode($resp_data, TRUE);
				/* echo "<pre>";
				print_r($resp_data);
				die(); */
                //If creation of URL is SUCCESS redirect to given URL and remember transaction id for later check
                if (is_array($resp_data) && isset($resp_data['result']) && $resp_data['result'] === 'SUCCESS') {
                    update_post_meta($order_id, 'netpay_transaction_id', $transaction_id);
                    header('Location:' . $resp_data['link']);
                }
                //Otherwise write that error happened and write note on order with reason if one was returned
                else {
                    if(is_array($resp_data) && isset($resp_data['result']) && $resp_data['result'] === 'ERROR' && isset($resp_data['explanation'])) {
                        $order->add_order_note(esc_html('NetPay payment creation problem<br/>Reason: ' . $resp_data['explanation'], 'tbi'));
                    }
                    return esc_html('There was an error creating payment. Please contact us or try again.', 'tbi');
                }
            }
            //If there was problem with connection show error to user
            else {
                return esc_html('There was an error creating payment. Please contact us or try again.', 'tbi');
            }
        }

        /**
         * Get User's Browser
         */
        function getBrowser()
        {
            $u_agent = $_SERVER['HTTP_USER_AGENT'];
            $bname = esc_html('Unknown', 'tbi');
            $platform = esc_html('Unknown', 'tbi');
            $version = "";

            //First get the platform
            if (preg_match('/linux/i', $u_agent)) {
                $platform = esc_html('linux', 'tbi');
            }
            elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {
                $platform = esc_html('mac', 'tbi');
            }
            elseif (preg_match('/windows|win32/i', $u_agent)) {
                $platform = esc_html('windows', 'tbi');
            }

            //Next get the name of the useragent yes seperately and for good reason
            if (preg_match('/MSIE/i', $u_agent) && !preg_match('/Opera/i', $u_agent)) {
                $bname = esc_html('Internet Explorer', 'tbi');
                $ub = esc_html("MSIE", "tbi");
            }
            elseif (preg_match('/Firefox/i', $u_agent)) {
                $bname = esc_html('Mozilla Firefox', 'tbi');
                $ub = esc_html("Firefox", "tbi");
            }
            elseif (preg_match('/Chrome/i', $u_agent)) {
                $bname = esc_html('Google Chrome', 'tbi');
                $ub = esc_html("Chrome", "tbi");
            }
            elseif (preg_match('/Safari/i', $u_agent)) {
                $bname = esc_html('Apple Safari', 'tbi');
                $ub = "Safari";
            }
            elseif (preg_match('/Opera/i', $u_agent)) {
                $bname = esc_html('Opera', 'tbi');
                $ub = esc_html("Opera", "tbi");
            }
            elseif (preg_match('/Netscape/i', $u_agent)) {
                $bname = esc_html('Netscape', 'tbi');
                $ub = esc_html("Netscape", "tbi");
            }

            //Finally get the correct version number
            $known = array('Version', $ub, 'other');
            $pattern = '#(?<browser>' . join('|', $known) .
                    ')[/ ]+(?<version>[0-9.|a-zA-Z.]*)#';
            if (!preg_match_all($pattern, $u_agent, $matches)) {
                //We have no matching number just continue
            }

            //See how many we have
            $i = count($matches['browser']);
            if ($i != 1) {
                //We will have two since we are not using 'other' argument yet
                //See if version is before or after the name
                if (strripos($u_agent, "Version") < strripos($u_agent, $ub)) {
                    $version = $matches['version'][0];
                }
                else {
                    $version = $matches['version'][1];
                }
            }
            else {
                $version = $matches['version'][0];
            }

            //Check if we have a number
            if ($version == null || $version == "") {
                $version = "?";
            }

            return array(
                'userAgent' => $u_agent,
                'name' => $bname,
                'version' => $version,
                'platform' => $platform,
                'pattern' => $pattern
            );
        }

        /**
         * Function to get ISO Country Code for the 2 character country code
         */
        function getValidCountryCode($code)
        {
            $countries = array(
                'AF' => 'AFG',
                'AL' => 'ALB',
                'DZ' => 'DZA',
                'AD' => 'AND',
                'AO' => 'AGO',
                'AI' => 'AIA',
                'AQ' => 'ATA',
                'AG' => 'ATG',
                'AR' => 'ARG',
                'AM' => 'ARM',
                'AW' => 'ABW',
                'AU' => 'AUS',
                'AT' => 'AUT',
                'AZ' => 'AZE',
                'BS' => 'BHS',
                'BH' => 'BHR',
                'BD' => 'BGD',
                'BB' => 'BRB',
                'BY' => 'BLR',
                'BE' => 'BEL',
                'BZ' => 'BLZ',
                'BJ' => 'BEN',
                'BM' => 'BMU',
                'BT' => 'BTN',
                'BO' => 'BOL',
                'BA' => 'BIH',
                'BW' => 'BWA',
                'BV' => 'BVT',
                'BR' => 'BRA',
                'IO' => 'IOT',
                'VG' => 'VGB',
                'BN' => 'BRN',
                'BG' => 'BGR',
                'BF' => 'BFA',
                'BI' => 'BDI',
                'KH' => 'KHM',
                'CM' => 'CMR',
                'CA' => 'CAN',
                'CV' => 'CPV',
                'KY' => 'CYM',
                'CF' => 'CAF',
                'TD' => 'TCD',
                'CL' => 'CHL',
                'CN' => 'CHN',
                'CX' => 'CXR',
                'CC' => 'CCK',
                'CO' => 'COL',
                'KM' => 'COM',
                'CG' => 'COG',
                'CD' => 'COD',
                'CK' => 'COK',
                'CR' => 'CRI',
                'HR' => 'HRV',
                'CU' => 'CUB',
                'CY' => 'CYP',
                'CZ' => 'CZE',
                'DK' => 'DNK',
                'DJ' => 'DJI',
                'DM' => 'DMA',
                'DO' => 'DOM',
                'EC' => 'ECU',
                'EG' => 'EGY',
                'SV' => 'SLV',
                'GQ' => 'GNQ',
                'ER' => 'ERI',
                'EE' => 'EST',
                'ET' => 'ETH',
                'FK' => 'FLK',
                'FO' => 'FRO',
                'FJ' => 'FJI',
                'FI' => 'FIN',
                'FR' => 'FRA',
                'GF' => 'GUF',
                'PF' => 'PYF',
                'TF' => 'ATF',
                'GA' => 'GAB',
                'GM' => 'GMB',
                'GE' => 'GEO',
                'DE' => 'DEU',
                'GH' => 'GHA',
                'GI' => 'GIB',
                'GR' => 'GRC',
                'GL' => 'GRL',
                'GD' => 'GRD',
                'GP' => 'GLP',
                'GT' => 'GTM',
                'GN' => 'GIN',
                'GW' => 'GNB',
                'GY' => 'GUY',
                'HT' => 'HTI',
                'HM' => 'HMD',
                'HN' => 'VAT',
                'HK' => 'HKG',
                'HU' => 'HUN',
                'IS' => 'ISL',
                'IN' => 'IND',
                'ID' => 'IDN',
                'IR' => 'IRN',
                'IQ' => 'IRQ',
                'IE' => 'IRL',
                'IL' => 'ISR',
                'IT' => 'ITA',
                'CI' => 'CIV',
                'JM' => 'JAM',
                'JP' => 'JPN',
                'JO' => 'JOR',
                'KZ' => 'KAZ',
                'KE' => 'KEN',
                'KI' => 'KIR',
                'KW' => 'KWT',
                'KG' => 'KGZ',
                'LA' => 'LAO',
                'LV' => 'LVA',
                'LB' => 'LBN',
                'LS' => 'LSO',
                'LR' => 'LBR',
                'LY' => 'LBY',
                'LI' => 'LIE',
                'LT' => 'LTU',
                'LU' => 'LUX',
                'MO' => 'MAC',
                'MK' => 'MKD',
                'MG' => 'MDG',
                'MW' => 'MWI',
                'MY' => 'MYS',
                'MV' => 'MDV',
                'ML' => 'MLI',
                'MT' => 'MLT',
                'MH' => 'MHL',
                'MQ' => 'MTQ',
                'MR' => 'MRT',
                'MU' => 'MUS',
                'YT' => 'MYT',
                'MX' => 'MEX',
                'FM' => 'FSM',
                'MD' => 'MDA',
                'MC' => 'MCO',
                'MN' => 'MNG',
                'ME' => 'MNE',
                'MS' => 'MSR',
                'MA' => 'MAR',
                'MZ' => 'MOZ',
                'MM' => 'MMR',
                'NA' => 'NAM',
                'NR' => 'NRU',
                'NP' => 'NPL',
                'NL' => 'NLD',
                'AN' => 'ANT',
                'NC' => 'NCL',
                'NZ' => 'NZL',
                'NI' => 'NIC',
                'NE' => 'NER',
                'NG' => 'NGA',
                'NU' => 'NIU',
                'NF' => 'NFK',
                'KP' => 'PRK',
                'NO' => 'NOR',
                'OM' => 'OMN',
                'PK' => 'PAK',
                'PS' => 'PSE',
                'PA' => 'PAN',
                'PG' => 'PNG',
                'PY' => 'PRY',
                'PE' => 'PER',
                'PH' => 'PHL',
                'PN' => 'PCN',
                'PL' => 'POL',
                'PT' => 'PRT',
                'QA' => 'QAT',
                'RE' => 'REU',
                'RO' => 'ROM',
                'RU' => 'RUS',
                'RW' => 'RWA',
                'BL' => 'BLM',
                'SH' => 'SHN',
                'KN' => 'KNA',
                'LC' => 'LCA',
                'MF' => 'MAF',
                'PM' => 'SPM',
                'VC' => 'VCT',
                'SM' => 'SMR',
                'ST' => 'STP',
                'SA' => 'SAU',
                'SN' => 'SEN',
                'RS' => 'SRB',
                'SC' => 'SYC',
                'SL' => 'SLE',
                'SG' => 'SGP',
                'SK' => 'SVK',
                'SI' => 'SVN',
                'SB' => 'SLB',
                'SO' => 'SOM',
                'ZA' => 'ZAF',
                'GS' => 'SGS',
                'KR' => 'KOR',
                'SS' => 'SSD',
                'ES' => 'ESP',
                'LK' => 'LKA',
                'SD' => 'SDN',
                'SR' => 'SUR',
                'SJ' => 'SJM',
                'SZ' => 'SWZ',
                'SE' => 'SWE',
                'CH' => 'CHE',
                'SY' => 'SYR',
                'TW' => 'TWN',
                'TJ' => 'TJK',
                'TZ' => 'TZA',
                'TH' => 'THA',
                'TL' => 'TLS',
                'TG' => 'TGO',
                'TK' => 'TKL',
                'TO' => 'TON',
                'TT' => 'TTO',
                'TN' => 'TUN',
                'TR' => 'TUR',
                'TM' => 'TKM',
                'TC' => 'TCA',
                'TV' => 'TUV',
                'UG' => 'UGA',
                'UA' => 'UKR',
                'AE' => 'ARE',
                'GB' => 'GBR',
                'US' => 'USA',
                'UY' => 'URY',
                'UZ' => 'UZB',
                'VU' => 'VUT',
                'VA' => 'VAT',
                'VE' => 'VEN',
                'VN' => 'VNM',
                'WF' => 'WLF',
                'EH' => 'ESH',
                'WS' => 'WSM',
                'YE' => 'YEM',
                'ZM' => 'ZMB',
                'ZW' => 'ZWE',
                'PW' => 'PLW',
                'BQ' => 'BES',
                'CW' => 'CUW',
                'GG' => 'GGY',
                'IM' => 'IMN',
                'JE' => 'JEY',
                'SX' => 'SXM'
            );

            return $countries[$code];
        }

    }
	
	/**
	 * Custom currency and currency symbol
	 */
	add_filter( 'woocommerce_currencies', 'add_my_currency' );

	function add_my_currency( $currencies ) {
		 $currencies['GBP'] = __( 'United Kingdom', 'woocommerce' );
		 return $currencies;
	}

	add_filter('woocommerce_currency_symbol', 'add_my_currency_symbol', 10, 2);

	function add_my_currency_symbol( $currency_symbol, $currency ) {
		 switch( $currency ) {
			  case 'GBP': $currency_symbol = '£'; 
			  break;
		 }
		 return $currency_symbol;
	}

    /**
     * Add this Gateway to WooCommerce
     */
    function woocommerce_add_tbi_netpay_gateway($methods)
    {
        $methods[] = esc_html('WC_Tbi_Netpay', 'tbi');
        return $methods;
    }

    add_filter('woocommerce_payment_gateways', 'woocommerce_add_tbi_netpay_gateway');
}