<?php
/**
 * Soap Client using Microsoft's NTLM Authentication.
 *
 * Copyright (c) 2008 Invest-In-France Agency http://www.invest-in-france.org
 *
 * Author : Thomas Rabaix
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * @link http://rabaix.net/en/articles/2008/03/13/using-soap-php-with-ntlm-authentication
 * @author Thomas Rabaix
 *
 * @package php-ews
 * @subpackage NTLM
 */

/**
 * Soap Client using Microsoft's NTLM Authentication.
 */
class NTLMSoapClient extends SoapClient
{
    /**
     * cURL resource used to make the SOAP request
     *
     * @var resource
     */
    protected $ch;

    /**
     * Whether or not to validate ssl certificates
     *
     * @var boolean
     */
    protected $validate = false;

    public function __construct( $wsdl, $options=array() )
    {
        //parent::__construct( $wsdl, $options );
        $this->NTLMSocket = new NTLM_HTTP($this->host, $this->user, $this->password, $this->domain);
        $this->NTLMSocketResponse = $this->NTLMSocket->get($this->url);
        
        parent::__construct( $wsdl, $options );
    }
    
    /**
     * Performs a SOAP request
     *
     * @link http://php.net/manual/en/function.soap-soapclient-dorequest.php
     *
     * @param string $request the xml soap request
     * @param string $location the url to request
     * @param string $action the soap action.
     * @param integer $version the soap version
     * @param integer $one_way
     * @return string the xml soap response.
     */
    public function __doRequest($request, $location, $action, $version, $one_way = 0)
    {
        return $this->__doRequestHttp($request, $location, $action, $version, $one_way);
    }
    
    /**
     * Performs a SOAP request
     *
     * @link http://php.net/manual/en/function.soap-soapclient-dorequest.php
     *
     * @param string $request the xml soap request
     * @param string $location the url to request
     * @param string $action the soap action.
     * @param integer $version the soap version
     * @param integer $one_way
     * @return string the xml soap response.
     */
    public function __doRequestHttp($request, $location, $action, $version, $one_way = 0)
    {
        //FB::log('in __doRequest');
        //FB::log($request);
        //FB::log($location);
        //FB::log($action);
        //FB::log($version);
        /*
        $headers = array(
                'Method: POST',
                'Connection: Keep-Alive',
                'User-Agent: PHP-SOAP',
                'Content-Type: text/xml; charset=utf-8',
                'SOAPAction: "'.$action.'"',
        );
        */
        
        $headers = array(
                'Connection: Keep-Alive',
                'Keep-Alive: 300',
                'User-Agent: PHP-SOAP',
                'Content-Type: text/xml; charset=utf-8',
                'SOAPAction: "'.$action.'"',
        );

        // make the request, which returns the headers array from the response
        $this->__last_response_headers = $this->NTLMSocket->post($location, $headers, $request);
        
        $this->__last_request_headers = $this->NTLMSocket->last_send_headers;
        $this->__last_response = !empty($this->__last_response_headers['body']) ? trim($this->__last_response_headers['body']) : '';
        
        //FB::log($this);
        
        return $this->__last_response;
    }
    
    
    /**
     * Performs a SOAP request with Curl
     *
     * @link http://php.net/manual/en/function.soap-soapclient-dorequest.php
     *
     * @param string $request the xml soap request
     * @param string $location the url to request
     * @param string $action the soap action.
     * @param integer $version the soap version
     * @param integer $one_way
     * @return string the xml soap response.
     */
    public function __doRequestCurl($request, $location, $action, $version, $one_way = 0)
    {
        //FB::log('in __doRequestCurl');
        //FB::log($request);
        //FB::log($location);
        //FB::log($action);

        $headers = array(
                'Method: POST',
                'Connection: Keep-Alive',
                'User-Agent: PHP-SOAP',
                'Content-Type: text/xml; charset=utf-8',
                'SOAPAction: "'.$action.'"',
        );
        
        $this->__last_request_headers = $headers;
        $this->ch = curl_init($location);
/*        
//FB::log('NTLMSoapClient.validate');        
//FB::log($this->validate);
*/
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, $this->validate);
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, $this->validate);
        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($this->ch, CURLOPT_POST, true );
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, $request);
        curl_setopt($this->ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC | CURLAUTH_NTLM);
        curl_setopt($this->ch, CURLOPT_USERPWD, $this->user.':'.$this->password);
        
        $response = curl_exec($this->ch);
        $info = curl_getinfo($this->ch);
       
        
//FB::log('NTLMSoapClient.response');
//FB::log($response);                
//FB::log('NTLMSoapClient.info');
//FB::log($info);
/*
stream_wrapper_restore('https');
*/
        // TODO: Add some real error handling.
        // If the response if false than there was an error and we should throw
        // an exception.
        if ($response === false) {
            throw new EWS_Exception(
              'Curl error: ' . curl_error($this->ch),
              curl_errno($this->ch)
            );
        }

        return $response;
    }

    /**
     * Returns last SOAP request headers
     *
     * @link http://php.net/manual/en/function.soap-soapclient-getlastrequestheaders.php
     *
     * @return string the last soap request headers
     */
    public function __getLastRequestHeaders()
    {
        return implode('n', $this->__last_request_headers) . "\n";
    }

    /**
     * Sets whether or not to validate ssl certificates
     *
     * @param boolean $validate
     */
    public function validateCertificate($validate = true)
    {
        $this->validate = $validate;

        return true;
    }
    
    /**
     * Returns the response code from the last request
     *
     * @return integer
     */
    public function getResponseCode()
    {
        return $this->getResponseCodeHttp();
    }
    
    /**
     * Returns the response code from the last request
     *
     * @return integer
     */
    public function getResponseCodeHttp()
    {
        $last_response_code = 0;
    
        if (!empty($this->__last_response_headers['status'])) {
            $last_response_code = (int) $this->__last_response_headers['status'];
        }
    
        return $last_response_code;
    }
    
    /**
     * Returns the response code from the last request
     *
     * @return integer
     */
    public function getResponseCodeCurl()
    {
        return curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
    }
}
