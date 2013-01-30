<?php

/**
 * Copyless: DJ Maze http://dragonflycms.org/
 *
 * http://davenport.sourceforge.net/ntlm.html
 * http://www.dereleased.com/2009/07/25/post-via-curl-under-ntlm-auth-learn-from-my-pain/
 */

class NTLM_HTTP
{
	# flags
	const FLAG_UNICODE        = 0x00000001; # Negotiate Unicode
	const FLAG_OEM            = 0x00000002; # Negotiate OEM
	const FLAG_REQ_TARGET     = 0x00000004; # Request Target
//	const FLAG_               = 0x00000008; # unknown
	const FLAG_SIGN           = 0x00000010; # Negotiate Sign
	const FLAG_SEAL           = 0x00000020; # Negotiate Seal
	const FLAG_DATAGRAM       = 0x00000040; # Negotiate Datagram Style
	const FLAG_LM_KEY         = 0x00000080; # Negotiate Lan Manager Key
	const FLAG_NETWARE        = 0x00000100; # Negotiate Netware
	const FLAG_NTLM           = 0x00000200; # Negotiate NTLM
//	const FLAG_               = 0x00000400; # unknown
	const FLAG_ANONYMOUS      = 0x00000800; # Negotiate Anonymous
	const FLAG_DOMAIN         = 0x00001000; # Negotiate Domain Supplied
	const FLAG_WORKSTATION    = 0x00002000; # Negotiate Workstation Supplied
	const FLAG_LOCAL_CALL     = 0x00004000; # Negotiate Local Call
	const FLAG_ALWAYS_SIGN    = 0x00008000; # Negotiate Always Sign
	const FLAG_TYPE_DOMAIN    = 0x00010000; # Target Type Domain
	const FLAG_TYPE_SERVER    = 0x00020000; # Target Type Server
	const FLAG_TYPE_SHARE     = 0x00040000; # Target Type Share
	const FLAG_NTLM2          = 0x00080000; # Negotiate NTLM2 Key
	const FLAG_REQ_INIT       = 0x00100000; # Request Init Response
	const FLAG_REQ_ACCEPT     = 0x00200000; # Request Accept Response
	const FLAG_REQ_NON_NT_KEY = 0x00400000; # Request Non-NT Session Key
	const FLAG_TARGET_INFO    = 0x00800000; # Negotiate Target Info
//	const FLAG_               = 0x01000000; # unknown
//	const FLAG_               = 0x02000000; # unknown
//	const FLAG_               = 0x04000000; # unknown
//	const FLAG_               = 0x08000000; # unknown
//	const FLAG_               = 0x10000000; # unknown
	const FLAG_128BIT         = 0x20000000; # Negotiate 128
	const FLAG_KEY_EXCHANGE   = 0x40000000; # Negotiate Key Exchange
	const FLAG_56BIT          = 0x80000000; # Negotiate 56

	protected $user;
	protected $password;
	protected $domain;
	protected $workstation;

	protected $host;
	protected $socket;
	protected $msg1;
	protected $msg3;

	public $last_send_headers;

	function __construct($host, $user, $password, $domain='', $workstation='')
	{
		if (!function_exists($function='mcrypt_encrypt'))
		{
			throw new Exception('NTLM Error: the required "mcrypt" extension is not available');
		}

		$port = 443;
		if (preg_match('#^(.*)?:(\d+)?$#D', $host, $match)) {
			$host = (empty($match[1]) ? '127.0.0.1' : $match[1]);
			$port = (empty($match[2]) ? $port : intval($match[2]));
		}
		
		if (!$this->socket = pfsockopen('ssl://'.$host, $port, $errno, $errstr, 30))
		{
			throw new Exception("NTLM_HTTP failed to open. Error {$errno}: {$errstr}");
		}
		$this->host        = $host.':'.$port;
		$this->user        = $user;
		$this->password    = $password;
		$this->domain      = $domain;
		$this->workstation = $workstation;
		
		//FB::log($this);
	}

	function __destruct()
	{
		if ($this->socket) {
			fclose($this->socket);
			$this->socket = null;
		}
	}

	public function get($uri, $add_headers=array())
	{
		$headers = array(
			'GET '.$uri.' HTTP/1.1',
			'Host: '.$this->host,
//			'Accept: */*',
//			'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
//			'Accept-Encoding: gzip,deflate',
//			'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7',
//			'Connection: keep-alive',
//			'Cache-Control: max-age=0, max-age=0',
//			'Keep-Alive: 300',
//			'User-Agent: '.$_SERVER['HTTP_USER_AGENT'],
		);
		foreach ($add_headers as $k => $v) { if ('Host'!=$k) { $headers[] = $k.': '.$v; } }
		$headers = implode("\r\n", $headers);
		$this->send_headers($headers . ($this->msg3?"\r\nAuthorization: NTLM {$this->msg3}":''));

		$response = $this->get_response_head();

		if (401 === $response['status']) {
			$NTLM = $response['NTLM'];
			$this->msg3 = null;
			if (!$NTLM) {
				# Send The Type 1 Message
				$this->send_headers($headers . "\r\nAuthorization: NTLM {$this->TypeMsg1()}");
				$response = $this->get_response_head();
				if (!$NTLM = $response['NTLM']) {
					throw new Exception('NTLM Authorization failed at step 1');
				}
			}
			if ($NTLM) {
				# Send The Type 3 Message
				$this->send_headers($headers . "\r\nAuthorization: NTLM {$this->TypeMsg3($NTLM)}");
				$response = $this->get_response_head();
			}
		}

		if (400 > $response['status'] && !empty($response['headers']['Content-Length'])) {
			$l = $response['headers']['Content-Length'];
			while ($l && !feof($this->socket) && false !== ($buf=fread($this->socket, min($l,8192)))) {
				$response['body'] .= $buf;
				$l -= strlen($buf);
			}
		}

		return $response;
	}

	public function post($uri, $add_headers=array(), $data)
	{
		$headers = array_merge(array(
			'POST '.$uri.' HTTP/1.1',
			'Host: '.$this->host,
//			'Accept: */*',
//			'Accept-Encoding: gzip,deflate',
//			'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7',
//			'Connection: keep-alive',
//			'Cache-Control: max-age=0, max-age=0',
//			'Keep-Alive: 300',
//			'User-Agent: '.$_SERVER['HTTP_USER_AGENT'],
		), $add_headers);
//		foreach ($add_headers as $k => $v) { if ('Host'!=$k) { $headers[] = $k.': '.$v; } }
		$headers = implode("\r\n", $headers);
		$this->send_headers($headers
			.($this->msg3?"\r\nAuthorization: NTLM {$this->msg3}":'')
			."\r\nContent-Length: ".strlen($data)
		);
		fwrite($this->socket, $data);
//FB::log('http.post.headers');		
//FB::log(nl2br($this->last_send_headers));
		$response = $this->get_response_head();
//FB::log('http.post.response.1');
//FB::log($response);
		if (401 === $response['status']) {
			$NTLM = $response['NTLM'];
			$this->msg3 = null;
			if (!$NTLM) {
				# Send The Type 1 Message
				$this->send_headers($headers . "\r\nAuthorization: NTLM {$this->TypeMsg1()}\r\nContent-Length: 0");
				$response = $this->get_response_head();
//FB::log('http.post.response.2');
//FB::log($response);				
				if (!$NTLM = $response['NTLM']) {
					throw new Exception('NTLM Authorization failed at step 1');
				}
			}
			if ($NTLM) {
				# Send The Type 3 Message
				$this->send_headers($headers . "\r\nAuthorization: NTLM {$this->TypeMsg3($NTLM)}\r\nContent-Length: ".strlen($data));
				fwrite($this->socket, $data);
				$response = $this->get_response_head();
//FB::log('http.post.response.3');
//FB::log($response);
			}
		}

		if (400 > $response['status'] && !empty($response['headers']['Content-Length'])) {
			$l = $response['headers']['Content-Length'];
			while ($l && !feof($this->socket) && false !== ($buf=fread($this->socket, min($l,8192)))) {
				$response['body'] .= $buf;
				$l -= strlen($buf);
			}
		}

		return $response;
	}

	protected function get_response_head()
	{
		$head = array(
			'status'  => intval(substr(fgets($this->socket,1024),9,3)),
			'headers' => array(),
			'NTLM'    => null,
			'body'    => null
		);
		while (!feof($this->socket) && ('' != trim($line = fgets($this->socket, 1024))))
		{
			$p = strpos($line,':');
			if (strpos($line,': NTLM')) {
				$head['NTLM'] = trim(substr($line,$p+6));
			} else {
				$head['headers'][substr($line,0,$p)] = trim(substr($line,$p+1));
			}
		}
		if (401 === $head['status'] && is_null($head['NTLM'])) {
			throw new Exception('NTLM Authorization not allowed on server');
		}
		return $head;
	}

	protected function send_headers($headers)
	{
		$headers = $this->last_send_headers = trim($headers);
		return fwrite($this->socket, $headers."\r\n\r\n");
	}

	public function TypeMsg1()
	{
		if (!$this->msg1)
		{
			$flags = self::FLAG_UNICODE | self::FLAG_OEM | self::FLAG_REQ_TARGET | self::FLAG_NTLM;
			// self::FLAG_ALWAYS_SIGN | self::FLAG_NTLM2 | self::FLAG_128BIT | self::FLAG_56BIT;
			$offset = 32;

			$d_length = strlen($this->domain);
			$d_offset = $d_length ? $offset : 0;
			if ($d_length) {
				$offset += $d_length;
				$flags |= self::FLAG_DOMAIN;
			}

			$w_length = strlen($this->workstation);
			$w_offset = $w_length ? $offset : 0;
			if ($w_length) {
				$offset += $w_length;
				$flags |= self::FLAG_WORKSTATION;
			}

			$this->msg1 = base64_encode(
				"NTLMSSP\0".
				"\x01\x00\x00\x00". # Type 1 Indicator
				pack('V',$flags).
				pack('vvV',$d_length,$d_length,$d_offset).
				pack('vvV',$w_length,$w_length,$w_offset).
//				"\x00\x00\x00\x0f". # OS Version ???
				$this->workstation.
				$this->domain
			);
		}
		return $this->msg1;
	}

	protected function TypeMsg3($ntlm_response)
	{
		if (!$this->msg3)
		{
			# Handel the server Type 2 Message
			$msg2 = base64_decode($ntlm_response);
			$headers = unpack('a8ID/Vtype/vtarget_length/vtarget_space/Vtarget_offset/Vflags/a8challenge/a8context/vtargetinfo_length/vtargetinfo_space/Vtargetinfo_offset/cOS_major/cOS_minor/vOS_build', $msg2);
			if ($headers['ID'] != 'NTLMSSP') {
				exit('Incorrect NTLM Type 2 Message');
				return false;
			}
			$headers['challenge'] = substr($msg2,24,8);
//			$headers['challenge'] = str_pad($headers['challenge'],8,"\0");

			# Build Type 3 Message
			$flags  = self::FLAG_UNICODE | self::FLAG_NTLM | self::FLAG_REQ_TARGET;
			$offset = 64;
			$challenge = $headers['challenge'];

			$target         = self::ToUnicode($this->domain);
			$target_length  = strlen($target);
			$target_offset  = $offset;
			$offset += $target_length;

			$user         = self::ToUnicode($this->user);
			$user_length  = strlen($user);
			$user_offset  = $user_length ? $offset : 0;
			$offset += $user_length;

			$workstation        = self::ToUnicode($this->workstation);
			$workstation_length = strlen($workstation);
			$workstation_offset = $workstation_length ? $offset : 0;
			$offset += $workstation_length;

			$lm = ''; # self::DESencrypt(str_pad(self::LMhash($this->password),21,"\0"), $challenge);
			$lm_length = strlen($lm);
			$lm_offset = $lm_length ? $offset : 0;
			$offset += $lm_length;

			$password = self::ToUnicode($this->password);
//			$ntlm = self::DESencrypt(str_pad(mhash(MHASH_MD4,$password,true),21,"\0"), $challenge);
			$ntlm = self::DESencrypt(str_pad(hash('md4',$password,true),21,"\0"), $challenge);
			$ntlm_length = strlen($ntlm);
			$ntlm_offset = $ntlm_length ? $offset : 0;
			$offset += $ntlm_length;

			$session = '';
			$session_length = strlen($session);
			$session_offset = $session_length ? $offset : 0;
			$offset += $session_length;

			$this->msg3 = base64_encode(
				"NTLMSSP\0".
				"\x03\x00\x00\x00".
				pack('vvV',$lm_length,$lm_length,$lm_offset).
				pack('vvV',$ntlm_length,$ntlm_length,$ntlm_offset).
				pack('vvV',$target_length,$target_length,$target_offset).
				pack('vvV',$user_length,$user_length,$user_offset).
				pack('vvV',$workstation_length,$workstation_length,$workstation_offset).
				pack('vvV',$session_length,$session_length,$session_offset).
				pack('V',$flags).
				$target.
				$user.
				$workstation.
				$lm.
				$ntlm
			);
		}
		return $this->msg3;
	}

	protected static function LMhash($str)
	{
		$string = strtoupper(substr($str,0,14));
		return self::DESencrypt($str);
	}

	protected static function DESencrypt($str, $challenge='KGS!@#$%')
	{
		$is = mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_ECB);
		$iv = mcrypt_create_iv($is, MCRYPT_RAND);

		$des = '';
		$l = strlen($str);
		$str = str_pad($str,ceil($l/7)*7,"\0");
		for ($i=0; $i<$l; $i+=7)
		{
			$bin = '';
			for ($p=0; $p<7; ++$p) {
				$bin .= str_pad(decbin(ord($str[$i+$p])),8,'0',STR_PAD_LEFT);
			}

			$key = '';
			for ($p=0; $p<56; $p+=7)
			{
				$s = substr($bin,$p,7);
				$key .= chr(bindec($s.((substr_count($s,'1') % 2) ? '0' : '1')));
			}

			$des .= mcrypt_encrypt(MCRYPT_DES, $key, $challenge, MCRYPT_MODE_ECB, $iv);
		}
		return $des;
	}

	protected static function ToUnicode($ascii)
	{
		return mb_convert_encoding($ascii,'UTF-16LE','auto');
		$str = '';
		for ($a=0; $a<strlen($ascii); ++$a) { $str .= substr($ascii,$a,1)."\0"; }
		return $str;
	}
}
