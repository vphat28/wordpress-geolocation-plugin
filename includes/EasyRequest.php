<?php
/**
 * Simple Http Client inspired by PSR-7
 *
 * @author Phan Thanh Cong <ptcong90@gmail.com>
 */
class EasyRequest
{
    const BOUNDARY_PLACEHOLDER = '##BOUNDARY##';

    /**
     * Array of options.
     *
     * @var array
     */
    protected $options = array(
        'handler'          => null,  // null|string - "socket" or "curl", null to use default.
        'method'           => 'GET', // string - HTTP method
        'url'              => '',    // string - Target url
        'nobody'           => false, // boolean Gets header only
        'follow_redirects' => 0,     // integer|true - True to follows all of redirections.
        'protocol_version' => '1.1', // string
        'timeout'          => 10,    // integer - Timeout in seconds
        'user_agent'       => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:38.0) Gecko/20100101 Firefox/38.0',
        'auth'             => null,    // null|string - An Auth Basic "user:password"
        'proxy'            => null,    // null|string - A proxy with format "ip:port"
        'proxy_userpwd'    => null,    // null|string - User password with format "user:password"
        'proxy_type'       => 'http',  // string - Must be one of "http" or "sock5"
        'headers'          => array(), // array
        'cookies'          => array(), // array
        'json'             => false,   // false|string String json
        'body'             => '',      // string|resource
        'query'            => array(), // array
        'form_params'      => array(), // array
        'multipart'        => array(), // array
        'curl'             => array(),
    );

    /**
     * Array of request info.
     * After request sent, $request will contains the keys:
     * [
     *     uri => ...,
     *     uriInfo => ...,
     *     protocol_version => ...,
     *     method => ...,
     *     headers => ...,
     *     body => ...
     * ].
     *
     * @var null|array
     */
    public $request;

    /**
     * Array of response info.
     * After request sent, $response may be null or an array that
     * contains the keys
     * [
     *     headers => [
     *         protocol_version => ...,
     *         status => ...,
     *         reason => ...,
     *         headers => ...,
     *     ],
     *     body => ...
     * ].
     *
     * @var null|array
     */
    public $response;

    /**
     * Array of all requests.
     *
     * @var array
     */
    protected $redirects = array(
        'count'    => 0,
        'urls'     => array(),
        'cookies'  => array(),
        'requests' => array(), // [self]
    );

    /**
     * @var array
     */
    protected $debugInfo = array(
        'time_start'   => null,    // null|float time start sending
        'time_process' => null,    // null|float time for execute sending request
        'handler'      => null,
        'errors'       => array(), // array error message while sending reqeuest.
    );

    /**
     * Used for saving tempopary data.
     *
     * @var array
     */
    private $builder = array(
        'headers'     => array(),
        'query'       => array(),
        'form_params' => array(),
    );

    /**
     * Create an instance.
     *
     * @param string $method
     * @param string $url
     */
    private function __construct()
    {
    }

    /**
     * Set options.
     *
     * @param string|array $key
     * @param mixed|null   $value
     *
     * @return self
     *
     * @throws InvalidArgumentException If key is invalid.
     */
    public function setOptions($key, $value = null)
    {
        if (is_array($key)) {
            foreach ($key as $k => $v) {
                $this->setOptions($k, $v);
            }
        } elseif (!array_key_exists($key, $this->options)) {
            throw new InvalidArgumentException(sprintf('Option "%s" is invalid.', $key));
        } else {
            $this->options[$key] = $value;
        }

        return $this;
    }

    /**
     * Gets option by specified key.
     * If key is not given, returns all options.
     *
     * @param null|string $key
     *
     * @return mixed
     */
    public function getOptions($key = null)
    {
        if ($key === null) {
            return $this->options;
        } elseif (!array_key_exists($key, $this->options)) {
            throw new InvalidArgumentException(sprintf('Option "%s" is invalid.', $key));
        }

        return $this->options[$key];
    }

    /**
     * Create an instance.
     *
     * @param string $url|$method
     * @param string $method|$url
     * @param array  $options
     *
     * @return self
     */
    public static function create($url, $method = 'GET', $options = array())
    {
        // new style
        if (strpos($method, '://')) {
            $temp = $url;
            $url = $method;
            $method = $temp;
        }

        $object = new self;

        // Ensure that there options will not be overrided if we set them via both
        // options and helper method
        $params = array(
            'form_params' => 'withFormParam',
            'query'       => 'withQuery'
        );
        foreach ($params as $key => $setter) {
            if (isset($options[$key])) {
                $object->$setter($object->getParamsAsString($options[$key]));
                unset($options[$key]);
            }
        }
        if (!empty($options['headers'])) {
            foreach ($options['headers'] as $name => $values) {
                if (is_int($name)) {
                    list($name, $value) = explode(':', $values, 2);
                    $object->withHeader($name, $value);
                } else {
                    $object->withHeader($name, $values);
                }
            }
        }

        if (!empty($options['cookies']) && is_string($options['cookies'])) {
            $object->withStringCookies($options['cookies']);
            unset($options['cookies']);
        }

        return $object->setOptions(array('method' => strtoupper($method), 'url' => $url) + $options);
    }

    /**
     * Dynamic method to creating and sending request quickly.
     *
     * @param string $method
     * @param array  $arguments
     *
     * @return self
     *
     * @throws Exception if method given is not defined.
     */
    public static function __callStatic($method, $arguments)
    {
        static $methods = array(
            'OPTIONS' => 1,
            'GET'     => 1,
            'HEAD'    => 1,
            'POST'    => 1,
            'PUT'     => 1,
            'DELETE'  => 1,
            'TRACE'   => 1,
            'CONNECT' => 1
        );
        if (!empty($methods[strtoupper($method)])) {
            return self::create($method, $arguments[0], isset($arguments[1]) ? $arguments[1] : array())->send();
        }
        throw new Exception(sprintf('Method "%s" is not defined.', $method));
    }

    /*
     * Execute sending request.
     *
     * @return self
     */
    public function send()
    {
        list($options, $request) = $this->prepareRequest();

        if (empty($request['uri'])) {
            throw new Exception('Request URI cannot be empty.');
        }

        // update sanitized options
        $this->options = $options;

        $this->request = $request;
        $this->response = null;

        $handler = $this->getHandler();
        $sendMethod = sprintf('sendWith%s', ucfirst($handler));

        $this->debugInfo['handler'] = $handler;
        $this->debugInfo['time_start'] = microtime(true);

        $info = $this->$sendMethod($this->request);

        $this->debugInfo['time_process'] = microtime(true) - $this->debugInfo['time_start'];

        if ($info !== false) {
            $this->response = array(
                'header' => $info[0],
                'body'   => $info[1]
            );
            $this->followRedirects();
        }

        return $this;
    }

    protected function followRedirects()
    {
        $client = clone $this;
        while (($this->options['follow_redirects'] === true
                || $this->options['follow_redirects'] > $this->redirects['count'])
            && $nextUrl = $client->getResponseHeaderLine('Location')
        ) {
            $nextUrl = $this->getAbsoluteUrl($nextUrl, $client->options['url']);

            if ($this->redirects['count'] === 0) {
                $this->redirects['urls'][] = $client->options['url'];
                $this->redirects['requests'][] = $client;
                $this->redirects['cookies'] = array_values($client->options['cookies']);
                $this->collectResponseCookies($this->redirects['cookies'], $client->getResponseArrayCookies());
            }

            $reuseOptions = array(
                'nobody', 'protocol_version', 'timeout', 'user_agent', 'auth', 'headers',
                'proxy', 'proxy_userpwd', 'proxy_type', 'query'
            );

            $options = array('cookies' => $this->redirects['cookies']);
            foreach ($reuseOptions as $key) {
                $options[$key] = $this->options[$key];
            }

            $client = self::create('GET', $nextUrl, $options)->send();

            // assign new response
            $this->request = $client->request;
            $this->response = $client->response;

            $this->redirects['count']++;
            $this->redirects['urls'][] = $client->options['url'];
            $this->redirects['requests'][] = $client;

            $this->collectResponseCookies($this->redirects['cookies'], $client->getResponseArrayCookies());
        }
    }

    private function collectResponseCookies(&$collection, $cookies)
    {
        if (!$cookies) {
            return;
        }

        foreach ($collection as $oldKey => $oldValue) {
            foreach ($cookies as $newKey => $newValue) {
                if ($oldValue['Name'] === $newValue['Name']
                    && $oldValue['Path'] === $newValue['Path']
                    && $oldValue['Domain'] === $newValue['Domain']
                    && $oldValue['Secure'] === $newValue['Secure']
                    && $oldValue['HttpOnly'] === $newValue['HttpOnly']
                ) {
                    // use newer value
                    $collection[$oldKey] = $newValue;
                    unset($cookies[$newKey]);
                }
            }
        }
        $collection = array_merge($collection, $cookies);
    }

    /**
     * Return current url.
     *
     * @return string
     */
    public function getCurrentUrl()
    {
        return $this->getRedirectedCount()
            ? end($this->redirects['urls'])
            : $this->options['url'];
    }

    /**
     * Returns collection cookies of all requests.
     *
     * @return array
     */
    public function getAllResponseCookies()
    {
        return $this->getRedirectedCount()
            ? $this->getRedirectedCookies()
            : $this->getResponseArrayCookies();
    }

    /**
     * Gets redirected count.
     *
     * @return integer
     */
    public function getRedirectedCount()
    {
        return $this->redirects['count'];
    }

    /**
     * Array of redirected urls.
     *
     * @return string[]
     */
    public function getRedirectedUrls()
    {
        return $this->redirects['urls'];
    }

    /**
     * Array of all cookies.
     *
     * @return array
     */
    public function getRedirectedCookies()
    {
        return $this->redirects['cookies'];
    }

    /**
     * Array of all requests.
     *
     * @return array
     */
    public function getRedirectedRequests()
    {
        return $this->redirects['requests'];
    }

    /**
     * Gets debug informartions.
     *
     * @param null|string $key
     *
     * @return array
     */
    public function getDebugInfo($key = null)
    {
        if ($key !== null) {
            return $this->debugInfo[$key];
        }

        return $this->debugInfo;
    }

    /**
     * Return current request.
     *
     * @param null|string
     *
     * @return null|array
     */
    public function getRequest($key = null)
    {
        if ($key !== null) {
            return $this->request[$key];
        }

        return $this->request;
    }

    /**
     * Return current response.
     *
     * @param null|string
     *
     * @return null|array
     */
    public function getResponse($key = null)
    {
        if ($key !== null) {
            return $this->response[$key];
        }

        return $this->response;
    }

    /**
     * Returns response body.
     *
     * @return string
     */
    public function __toString()
    {
        return !$this->response ? '' : $this->getResponseBody();
    }

    /**
     * Gets response body text.
     *
     * @return string|false False if has no response
     */
    public function getResponseBody()
    {
        return !$this->response ? false : $this->response['body'];
    }

    /**
     * Gets all response headers as string[].
     *
     * @return string[]|false False if has no response
     */
    public function getResponseHeaders()
    {
        return !$this->response ? false : $this->getHeadersAsLines($this->response['header']['headers']);
    }

    /**
     * Gets response header lines by specified name.
     *
     * @param string $name Case-insensitive
     *
     * @return array|false False if has no response
     */
    public function getResponseHeader($name)
    {
        return !$this->response ? false : $this->getHeaderAsLines($this->response['header']['headers'], $name);
    }

    /**
     * Gets a comma-separated string of the values for a single header.
     *
     * @param string $line
     *
     * @return string|false False if has no response
     */
    public function getResponseHeaderLine($line)
    {
        return !$this->response ? false : $this->getHeaderLine($this->response['header']['headers'], $line);
    }

    /**
     * Gets parsed cookies as array.
     *
     * @return array|false False if has no response
     */
    public function getResponseArrayCookies()
    {
        if (!$this->response) {
            return false;
        }
        $cookies = array();
        $cookieLines = $this->getHeaderAsLines($this->response['header']['headers'], 'Set-Cookie');
        foreach ($cookieLines as $cookie) {
            $cookies[] = $this->parseStringCookie($cookie);
        }

        return $cookies;
    }

    /**
     * Gets response cookies as semicolon-separated string.
     *
     * @return string|false False if has no response
     */
    public function getResponseCookies()
    {
        if (!$this->response) {
            return false;
        }
        $cookies = '';
        $cookieLines = $this->getHeaderAsLines($this->response['header']['headers'], 'Set-Cookie');
        foreach ($cookieLines as $cookie) {
            $cookies .= $this->getCookieAsString($this->parseStringCookie($cookie), false);
        }

        return trim($cookies);
    }

    /**
     * Gets response status code.
     *
     * @return integer|false False if has no response
     */
    public function getResponseStatus()
    {
        return !$this->response ? false : $this->response['header']['status'];
    }

    /**
     * Gets response phrase reason.
     *
     * @return string|false False if has no response
     */
    public function getResponseReason()
    {
        return !$this->response ? false : $this->response['header']['reason'];
    }

    /**
     * Gets response procotol version.
     *
     * @return string|false False if has no response
     */
    public function getResponseProtocolVersion()
    {
        return !$this->response ? false : $this->response['header']['protocol_version'];
    }

    /**
     * Sending request use socket.
     *
     * @param array $request
     *
     * @return false|array
     */
    protected function sendWithSocket(array $request)
    {
        static $ports = array( 'https' => 443, 'http' => 80, '' => 80);
        static $errorHandler = null;

        $uri = $request['uriInfo'];
        $host = ($uri['scheme'] == 'https' ? 'ssl://' : '').$uri['host'];
        $port = $uri['port'] ? $uri['port'] : $ports[$uri['scheme']];
        $path = $uri['path'].($uri['query'] ? '?'.$uri['query'] : '');

        $headers = $request['headers'];
        if ($this->options['proxy']) {
            list($host, $port) = explode(':', $this->options['proxy']);
            $path = $request['uri'];

            if ($this->options['proxy_userpwd']) {
                $headers[] = 'Proxy-Authorization: Basic '.base64_encode($this->options['proxy_userpwd']);
            }
        }
        $headers[] = 'Connection: close';

        $message = sprintf("%s %s HTTP/%s\r\n", $request['method'], $path, $request['protocol_version']);
        $message .= sprintf("Host: %s\r\n", $uri['host']);
        $message .= implode("\r\n", $headers)."\r\n";
        $message .= "\r\n";
        $message .= $request['body'];
        $message .= "\r\n\r\n";

        $errorHandler === null && $errorHandler = create_function('', '');
        // ignore warning
        $handler = set_error_handler($errorHandler);
        $stream = fsockopen($host, $port, $errno, $errstr, $this->options['timeout']);
        // restore error handler
        $handler ? set_error_handler($handler) : restore_error_handler();

        if (!$stream) {
            if ($errstr) {
                $this->debugInfo['errors'][] = sprintf('ERROR: %d - %s.', $errno, $errstr);
            } else {
                $this->debugInfo['errors'][] = sprintf('ERROR: Cannot connect to "%s:%s"', $host, $port);
            }

            return false;
        }
        fwrite($stream, $message);

        $headers = $body = '';
        do {
            $headers .= fgets($stream, 128);
        } while (strpos($headers, "\r\n\r\n") === false);

        $headers = $this->parseResponseHeaders($headers);

        if (!$this->options['nobody']) {
            while (!feof($stream)) {
                $body .= fgets($stream);
            }
            fclose($stream);

            if ($this->getHeaderLine($headers['headers'], 'Transfer-Encoding') == 'chunked') {
                $len = strlen($body);
                $outData = '';
                $pos = 0;
                while ($pos < $len) {
                    $rawnum = substr($body, $pos, strpos(substr($body, $pos), "\r\n") + 2);
                    $num = hexdec(trim($rawnum));
                    $pos += strlen($rawnum);
                    $chunk = substr($body, $pos, $num);
                    $outData .= $chunk;
                    $pos += strlen($chunk);
                }
                $body = $outData;
            }
        }

        return array($headers, $body);
    }

    /**
     * Sending request use curl.
     *
     * @param array $request
     *
     * @return false|array
     */
    protected function sendWithCurl(array $request)
    {
        $curlOptions = array(
            CURLOPT_CUSTOMREQUEST  => $request['method'],
            CURLOPT_URL            => $request['uri'],
            CURLOPT_HEADER         => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_ENCODING       => 'gzip, deflate',
            CURLOPT_NOBODY         => $this->options['nobody'],
            CURLOPT_TIMEOUT        => $this->options['timeout'],
            CURLOPT_HTTPHEADER     => $request['headers'],
        );

        if ($request['protocol_version'] == '1.0') {
            $curlOptions[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_1_0;
        } else {
            $curlOptions[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_1_1;
        }

        if ($body = $request['body']) {
            $curlOptions[CURLOPT_POSTFIELDS] = $body;
        }

        if ($this->options['proxy']) {
            $curlOptions[CURLOPT_PROXY] = $this->options['proxy'];

            static $proxyTypeOptions = array(
                'http'  => CURLPROXY_HTTP,
                'sock5' => CURLPROXY_SOCKS5
            );
            $curlOptions[CURLOPT_PROXYTYPE] = $proxyTypeOptions[$this->options['proxy_type']];

            if ($this->options['proxy_userpwd']) {
                $curlOptions[CURLOPT_PROXYUSERPWD] = $this->options['proxy_userpwd'];
            }
        }
        // add curl extra options
        $curlOptions += $this->options['curl'];

        $ch = curl_init();
        curl_setopt_array($ch, $curlOptions);
        $response = curl_exec($ch);

        if ($response === false) {
            $this->debugInfo['errors'][] = sprintf('ERROR: %d - %s.', curl_errno($ch), curl_error($ch));

            return false;
        }
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $headers = (string) substr($response, 0, $headerSize);
        $body = (string) substr($response, $headerSize);

        $headers = $this->parseResponseHeaders($headers);

        return array($headers, $body);
    }

    protected function parseResponseHeaders($headers)
    {
        $lines = array_filter(explode("\r\n", $headers));
        preg_match('#^HTTP/([\d\.]+)\s(\d+)\s(.*?)$#i', array_shift($lines), $match);

        $out = array(
            'protocol_version' => $match[1],
            'status'           => (int) $match[2],
            'reason'           => $match[3],
            'headers'          => array(),
        );
        $this->addHeaderToArray($out['headers'], $lines, null);

        return $out;
    }

    public function prepareRequest()
    {
        // this method may called in public to track what will be sent
        // but this thing should not effect to current object
        $clone = clone $this;

        $uri = $clone->parseUri($clone->options['url']);
        if ($clone->options['query']) {
            $uri['query'] = trim($uri['query'].'&'.$clone->getParamsAsString($clone->options['query']), '&');
        }
        $request = array(
            'protocol_version' => $clone->options['protocol_version'],
            'method'           => strtoupper($clone->options['method']),
            'uri'              => $clone->getUriAsString($uri),
            'uriInfo'          => $uri,
        );
        // update url option.
        $clone->options['url'] = $request['uri'];

        // prepare body as json
        if ($clone->options['json']) {
            !$clone->hasHeader('Content-Type')
                && $clone->withHeader('Content-Type', 'application/json');
            $clone->options['body'] = $clone->options['json'];
        }

        // prepare body
        $body = $params = $boundary = '';

        if ($clone->options['form_params']) {
            $params = $clone->getParamsAsString($clone->options['form_params']);
        }
        if ($clone->options['multipart']) {
            $boundary = uniqid();
            !$clone->hasHeader('Content-Type')
                && $clone->withHeader('Content-Type', 'multipart/form-data; boundary='.$boundary);

            // form params -> multipart fields
            if (preg_match_all('#([^=&]+)=([^&]*)#i', $params, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $match) {
                    $clone->withMultipart(urldecode($match[1]), urldecode($match[2]));
                }
            }
            $body .= $clone->getMultipartAsString($boundary, $clone->options['multipart']);
        } elseif ($params) {
            !$clone->hasHeader('Content-Type')
                && $clone->withHeader('Content-Type', 'application/x-www-form-urlencoded');

            $body .= $params;
        }
        if ($clone->options['body']) {
            $body .= $clone->getBodyAsString($clone->options['body']);
        }
        if ($body) {
            // correct method to send request with body
            if ($request['method'] == 'GET' || $request['method'] == 'HEAD') {
                $request['method'] = 'POST';
            }
        }

        // prepare auth basic
        $clone->options['auth']
            && $clone->withHeader('Authorization', 'Basic '.base64_encode($clone->options['auth']));

        // prepare cookies
        $cookies = '';
        if ($clone->hasHeader('Cookie')) {
            // assign Cookie header to cookies option.
            foreach ($clone->getHeaderAsLines($clone->builder['headers'], 'Cookie') as $value) {
                $clone->withStringCookies($value);
            }
        }
        foreach ($clone->options['cookies'] as $cookie) {
            if ($clone->isCookieMatchesDomain($cookie, $uri['host'])
                && $clone->isCookieMatchesPath($cookie, $uri['path'])
            ) {
                $cookies .= $clone->getCookieAsString($cookie, false);
            }
        }

        $cookies && $clone->withHeader('Cookie', trim($cookies), false);
        $body && $clone->withHeader('Content-Length', strlen($body), false);

        // user agent
        $clone->withHeader('User-Agent', $clone->options['user_agent'], false);

        !$clone->hasHeader('Expect') && $body && $clone->withHeader('Expect', '');

        $headers = $clone->getHeadersAsLines($clone->builder['headers']);

        if ($boundary) {
            foreach ($headers as &$line) {
                $line = strtr($line, array(self::BOUNDARY_PLACEHOLDER => $boundary));
            }
            $body = strtr($body, array(self::BOUNDARY_PLACEHOLDER => $boundary));
        }

        $request += array(
            'headers' => $headers,
            'body'    => $body
        );

        return array($clone->options, $request);
    }

    /**
     * Sets request method.
     *
     * @param string $method
     *
     * @return self
     */
    public function withMethod($method)
    {
        return $this->setOptions('method', $method);
    }

    /**
     * Sets User-Agent option.
     *
     * @param string $userAgent
     *
     * @return self
     */
    public function withUserAgent($userAgent)
    {
        return $this->setOptions('user_agent', $userAgent);
    }

    /**
     * Sets auth option.
     *
     * @param string|null $auth user:pass
     *
     * @return self
     *
     * @throws InvalidArgumentException if value is invalid.
     */
    public function withAuth($auth)
    {
        if ($auth === null || preg_match('#[\w-_]+(?::[\w-_]+)?#', $auth)) {
            return $this->setOptions('auth', $auth);
        }

        throw new InvalidArgumentException('Auth must be one of: string with format "user:pass" or "null".');
    }

    /**
     * Sets proxy option.
     *
     * @param string      $proxy   ip:port
     * @param null|string $userPwd user:pass
     * @param string      $type    Must be one of "http", "sock5"
     *
     * @return self
     *
     * @throws InvalidArgumentException if proxy is invalid.
     */
    public function withProxy($proxy, $userPwd = null, $type = 'http')
    {
        if ($proxy === null || preg_match('#^\d+\.\d+\.\d+\.\d+:\d+$#', $proxy)) {
            return $this
                ->setOptions('proxy', $proxy)
                ->setOptions('proxy_userpwd', $userPwd)
                ->setOptions('proxy_type', $type);
        }
        throw new InvalidArgumentException('Proxy must be one of: string with format "ip:port" or "null".');
    }

    /**
     * Sets HTTP proxy
     *
     * @param string $proxy
     * @param null|string $userPwd
     *
     * @return self
     *
     * @throws InvalidArgumentException if proxy is invalid.
     */
    public function withHttpProxy($proxy, $userPwd = null)
    {
        return $this->withProxy($proxy, $userPwd, 'http');
    }

    /**
     * Sets Sock5 proxy
     *
     * @param string $proxy
     * @param null|string $userPwd
     *
     * @return self
     *
     * @throws InvalidArgumentException if proxy is invalid.
     */
    public function withSock5Proxy($proxy, $userPwd = null)
    {
        return $this->withProxy($proxy, $userPwd, 'sock5');
    }

    /**
     * Sets body option.
     *
     * @param string|resource $body
     *
     * @return self
     */
    public function withBody($body)
    {
        $this->options['json'] = false;

        return $this->setOptions('body', $body);
    }

    /**
     * Used to easily upload JSON encoded data as the body
     * of a request. A Content-Type header of application/json will be added
     * if no Content-Type header is already present on the message.
     *
     * @param array|string $json Json string or array
     *
     * @return self
     *
     * @throws InvalidArgumentException if value is invalid
     */
    public function withJson($json)
    {
        if (is_string($json)) {
            $json = json_decode($json, true);
            if ($json === null) {
                throw new InvalidArgumentException('Json value must be an array or json string.');
            }
        }
        $this->options['body'] = $this->options['json'] = json_encode($json);

        return $this;
    }

    /**
     * Set nobody option.
     *
     * @param boolean $nobody
     *
     * @return self
     */
    public function withNobody($nobody)
    {
        return $this->setOptions('nobody', (bool) $nobody);
    }

    /**
     * Sets follow redirects option.
     *
     * @param integer|true $maxRedirect
     *
     * @return self
     *
     * @throws InvalidArgumentException If value is not
     */
    public function withFollowRedirects($maxRedirect)
    {
        if ($maxRedirect === true || is_numeric($maxRedirect) && 0 <= $maxRedirect = intval($maxRedirect)) {
            return $this->setOptions('follow_redirects', $maxRedirect);
        }

        throw new InvalidArgumentException('Max redirect must be a digit number or "true".');
    }

    /**
     * Sets timeout.
     *
     * @param integer $timeout
     *
     * @return self
     *
     * @throws InvalidArgumentException if value is not a digit number.
     */
    public function withTimeout($timeout)
    {
        if (is_numeric($timeout) && 0 <= $timeout = intval($timeout)) {
            $this->setOptions('timeout', (int) $timeout);

            return $this;
        }
        throw new InvalidArgumentException('Timeout must be be a digit number.');
    }

    /**
     * Sets HTTP protocol version option.
     *
     * @param string $version
     *
     * @return self
     *
     * @throws InvalidArgumentException If version given is invalid.
     */
    public function withProtocolVersion($version)
    {
        static $validProtocolVersions = array(
            '1.0' => true,
            '1.1' => true,
            '2.0' => true,
        );
        if (empty($validProtocolVersions[$version])) {
            throw new Exception('Protocol version given is invalid.');
        }

        return $this->setOptions('protocol_version', $version);
    }

    /**
     * Set headers option.
     *
     * @param string|array         $name
     * @param string|string[]|null $value
     * @param boolean              $append
     *
     * @return self
     */
    public function withHeader($name, $values = null, $append = true)
    {
        $this->addHeaderToArray($this->builder['headers'], $name, $values, $append);

        return $this->setOptions('headers', $this->getHeadersAsLines($this->builder['headers']));
    }

    /**
     * Return current instance without the specified header.
     *
     * @param string $name Case-insensitive header field name to remove.
     *
     * @return self
     */
    public function withoutHeader($name)
    {
        $this->removeHeaderFromArray($this->builder['headers'], $name);

        return $this;
    }

    /**
     * Determine if current request has a header or not.
     *
     * @param string $name Case-insensitive
     *
     * @return boolean
     */
    public function hasHeader($name)
    {
        return $this->headerHasKey($this->builder['headers'], $name);
    }

    /**
     * Sets multiple cookies by semicolon-separated string.
     *
     * @param string $cookies "name1=value1; name2=value2"
     *
     * @return self
     */
    public function withStringCookies($cookies, $path = '/', $secure = false, $httpOnly = false)
    {
        $append = array(
            'Path'     => $path,
            'Secure'   => $secure,
            'HttpOnly' => $httpOnly
        );
        foreach ($this->parseStringCookies($cookies) as $c) {
            $this->options['cookies'][$c['Name']] = $c + $append;
        }

        return $this;
    }

    /**
     * Sets cookies option.
     *
     * @param string|array|array[] $name
     * @param null|string|array    $value
     * @param string               $path
     * @param boolean              $secure
     * @param boolean              $httpOnly
     *
     * @return self
     */
    public function withCookie($name, $value = null, $path = '/', $secure = false, $httpOnly = false)
    {
        $append = array(
            'Path'     => $path,
            'Secure'   => $secure,
            'HttpOnly' => $httpOnly
        );
        if (is_array($name)) {
            if ($this->isCookieData($name)) {
                $this->options['cookies'][$name] = $name + $append;
            } else {
                foreach ($name as $k => $v) {
                    $this->withCookie($k, $v);
                }
            }
        } elseif (is_string($name) && $value === null) {
            $c = $this->parseStringCookie($name);
            $this->options['cookies'][$c['Name']] = $c;
        } elseif (is_array($value) && $this->isCookieData($value)) {
            $this->options['cookies'][$value['Name']] = $value + $append;
        } else {
            $this->options['cookies'][$name] = array('Name'  => $name, 'Value' => $value) + $append;
        }

        return $this;
    }

    /**
     * Remove a cookie with given name.
     *
     * @param string $name
     *
     * @return self
     */
    public function withoutCookie($name)
    {
        unset($this->options['cookies'][$name]);

        return $this;
    }

    /**
     * Shortcut to add a multipart field with a file path.
     *
     * @param string      $name
     * @param string      $filePath
     * @param null|string $filename
     * @param string[]    $headers
     *
     * @return self
     */
    public function withFormFile($name, $filePath, $filename = null, $headers = array())
    {
        $headers = array('Content-Transfer-Encoding' => 'binary') + $headers;

        if ($type = $this->getFileType($filePath)) {
            $headers['Content-Type'] = $type;
        }

        return $this->withMultipart($name, fopen($filePath, 'r'), $filename ? $filename : basename($filePath), $headers);
    }

    /**
     * Sets multipart option.
     *
     * @param string          $name
     * @param string|resource $contents
     * @param null|string     $filename
     * @param array           $headers
     *
     * @return self
     */
    public function withMultipart($name, $contents, $filename = null, $headers = array())
    {
        $this->options['multipart'][$name] = array(
            'name'     => $name,
            'contents' => $contents,
            'filename' => $filename,
            'headers'  => $headers
        );

        return $this;
    }

    /**
     * Remove a multipart field from list.
     *
     * @param string $name
     *
     * @return self
     */
    public function withoutMultipart($name)
    {
        unset($this->options['multipart'][$name]);

        return $this;
    }

    /**
     * Sets query option.
     *
     * @param string|array $name
     * @param string|null  $value
     * @param boolean      $append
     *
     * @return self
     */
    public function withQuery($name, $value = null, $append = true)
    {
        $this->addParamToArray($this->builder['query'], $name, $value, $append);

        $options = $this->getParamsAsArray($this->builder['query']);

        return $this->setOptions('query', $options);
    }

    /**
     * Remove a query from list.
     *
     * @param string $name
     *
     * @return self
     */
    public function withoutQuery($name)
    {
        $this->removeParamFromArray($this->builder['query'], $name);

        $options = $this->getParamsAsArray($this->builder['query']);

        return $this->setOptions('query', $options);
    }

    /**
     * Sets param option.
     *
     * @param string|array $name
     * @param string|null  $value
     * @param boolean      $append
     *
     * @return self
     */
    public function withFormParam($name, $value = null, $append = true)
    {
        $this->addParamToArray($this->builder['form_params'], $name, $value, $append);

        $options = $this->getParamsAsArray($this->builder['form_params']);

        return $this->setOptions('form_params', $options);
    }

    /**
     * Remove a param from list.
     *
     * @param string $name
     *
     * @return self
     */
    public function withoutFormParam($name)
    {
        $this->removeParamFromArray($this->builder['form_params'], $name);

        $options = $this->getParamsAsArray($this->builder['form_params']);

        return $this->setOptions('form_params', $options);
    }

    /**
     * Used for adding query/form param to an array.
     *
     * @param array                &$builder
     * @param string|array         $name
     * @param null|string|string[] $value
     * @param boolean              $append
     *
     * @return void
     */
    protected function addParamToArray(&$builder, $name, $value = null, $append = true)
    {
        if ($value !== null) {
            if (!$append || !isset($builder[$name])) {
                $builder[$name] = array();
            }
            $builder[$name] = array_merge($builder[$name], (array) $value);
        } else {
            if (is_array($name)) {
                foreach ($name as $key => $value) {
                    if (!is_int($key)) {
                        $this->addParamToArray($builder, $key, $value, $append);
                    } else {
                        $this->addParamToArray($builder, $value, null, $append);
                    }
                }
            } elseif (is_string($name)) {
                $name = str_replace('+', '%2B', preg_replace_callback(
                    '#&[a-z]+;#',
                    create_function('$match', 'return rawurlencode($match[0]);'),
                    $name));
                $this->addParamToArray($builder, $this->parseStringParams($name), null, $append);
            }
        }
    }

    /**
     * Used for removing a param with specified name from array.
     *
     * @param array  &$builder
     * @param string $name
     *
     * @return void
     */
    protected function removeParamFromArray(&$builder, $name)
    {
        unset($builder[$name]);
    }

    /**
     * Used for adding headers to an array.
     *
     * @param array           &$builder
     * @param string|array    $name
     * @param string|string[] $values
     * @param boolean         $append
     */
    protected function addHeaderToArray(&$builder, $name, $values, $append = true)
    {
        if (is_array($name)) {
            foreach ($name as $key => $value) {
                if (is_int($key)) {
                    list($key, $value) = array_map('trim', explode(':', $value, 2));
                }
                $this->addHeaderToArray($builder, $key, $value, $append);
            }

            return;
        }

        $normalizedKey = $this->normalizeHeaderKey($name);

        if (!$append || !isset($builder[$normalizedKey])) {
            $builder[$normalizedKey] = array();
        }

        foreach ((array) $values as $value) {
            if (!is_string($value) && !is_numeric($value)) {
                throw new InvalidArgumentException('Header value must be a string or array of string.');
            }
            $builder[$normalizedKey][] = array(
                'key'   => $name,
                'value' => trim($value)
            );
        }
    }

    /**
     * Used for removing a header with specified name from array.
     *
     * @param array  &$builder
     * @param string $name     Case-insensitive
     *
     * @return void
     */
    protected function removeHeaderFromArray(&$builder, $name)
    {
        unset($builder[$this->normalizeHeaderKey($name)]);
    }

    /**
     * Determine if headers has a specified key.
     *
     * @param array  $builder
     * @param string $name    Case-insensitive
     *
     * @return boolean
     */
    protected function headerHasKey($builder, $name)
    {
        return array_key_exists($this->normalizeHeaderKey($name), $builder);
    }

    /**
     * Gets HTTP header messages as lines.
     *
     * @param array $builder
     *
     * @return array Array headers iteractively
     */
    protected function getHeadersAsLines(array $builder)
    {
        $out = array();
        foreach ($builder as $values) {
            foreach ($values as $value) {
                $out[] = sprintf('%s: %s', $value['key'], $value['value']);
            }
        }

        return $out;
    }

    /**
     * Gets header as lines.
     *
     * @param string $name
     *
     * @return array
     */
    protected function getHeaderAsLines(array $builder, $name)
    {
        $normallizedKey = $this->normalizeHeaderKey($name);

        $out = array();
        if (isset($builder[$normallizedKey])) {
            foreach ($builder[$normallizedKey] as $value) {
                $out[] = $value['value'];
            }
        }

        return $out;
    }

    /**
     * Normalize case-insensitive key.
     *
     * @param string $key
     *
     * @return string
     */
    protected function normalizeHeaderKey($key)
    {
        return strtr(strtolower($key), '_', '-');
    }

    /**
     * Retrieves a comma-separated string of the values for a single header.
     *
     * @param array  $builder
     * @param string $name    Case-insensitive header field name.
     *
     * @return string
     */
    protected function getHeaderLine($builder, $name)
    {
        $normallizedKey = $this->normalizeHeaderKey($name);

        $out = '';
        if (isset($builder[$normallizedKey])) {
            foreach ($builder[$normallizedKey] as $value) {
                $out .= ($out ? ',' : '').$value['value'];
            }
        }

        return $out;
    }

    /**
     * Gets params as array.
     *
     * @param array $dataBuilder
     *
     * @return array
     */
    protected function getParamsAsArray(array $dataBuilder)
    {
        $params = array();
        foreach ($dataBuilder as $key => $param) {
            if (count($param) == 1) {
                $params[$key] = $param[0];
            } else {
                $params[$key] = $param;
            }
        }

        return $params;
    }

    /**
     * Gets array of params as string.
     *
     * @param array $params
     *
     * @return string
     */
    protected function getParamsAsString(array $params)
    {
        if (PHP_VERSION_ID >= 50400) {
            return http_build_query($params, null, '&', PHP_QUERY_RFC3986);
        } else {
            return preg_replace_callback('#([^=&]+)=([^&]*)#i', create_function('$match',
                'return $match[1]."=".rawurlencode(urldecode($match[2]));'
            ), http_build_query($params));
        }
    }

    /**
     * This method to parse a query string to array, and
     * also cover an bug of `parse_str` built in PHP.
     *
     * @see
     *     @code:    parse_str('.a=1&.b=2', $array);
     *     @output : array('_a' => 1, '_b' => 2);
     *     @expect : array('.a' => 1, '.b' => 2);
     *
     * @param string $queryString
     * @param array  &$array
     */
    protected function parseStringParams($queryString, &$array = array())
    {
        if (empty($queryString)) {
            return array();
        }
        $array = array();
        foreach (explode('&', $queryString) as $query) {
            list($key, $value) = explode('=', $query, 2) + array('', '');
            $key = urldecode($key);
            if (preg_match_all('#\[([^\]]+)?\]#i', $key, $matches)) {
                $key = str_replace($matches[0], '', $key);
                if (!isset($array[$key])) {
                    $array[$key] = array();
                }
                $children = & $array[$key];
                $deth = array();
                foreach ($matches[1] as $sub) {
                    $sub = $sub !== '' ? $sub : count($children);
                    if (!array_key_exists($sub, $children)) {
                        $children[$sub] = array();
                    }
                    $children = & $children[$sub];
                }
                $children = urldecode($value);
            } else {
                $array[$key] = urldecode($value);
            }
        }

        return $array;
    }

    /**
     * Gets cookie defaults.
     *
     * @return array
     */
    protected function getCookieDefaults()
    {
        static $defauls = array(
            'Name'     => null,
            'Value'    => null,
            'Domain'   => null,
            'Path'     => '/',
            'Max-Age'  => null,
            'Expires'  => null,
            'Secure'   => false,
            'Discard'  => false,
            'HttpOnly' => false
        );

        return $defauls;
    }

    /**
     * Parse string of cookies "name1=value1; name2=value2;".
     *
     * @param string $values
     *
     * @return array Array of $cookie
     */
    public function parseStringCookies($values)
    {
        $array = array();
        if (preg_match_all('#(?:^|;)\s*([^=]+)=([^;]+)\s*?#', $values, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                list(, $name, $value) = $match;
                if (
                    !strcasecmp($name, 'Expires') && strtotime($value)
                    || !strcasecmp($name, 'Path') && urldecode($value) == $value
                    || preg_match('#Domain|Max-Age|Secure|Discard|HttpOnly#i', $value)

                ) {
                    continue;
                }
                $array[] = array('Name' => $name, 'Value' => $value) + $this->getCookieDefaults();
            }
        }

        return $array;
    }

    /**
     * Parse string cookie to array.
     *
     * @param string $value
     *
     * @return array $cookie
     */
    protected function parseStringCookie($value)
    {
        $data = $this->getCookieDefaults();
        if (is_string($value) && preg_match_all('#([^=;\s]+)(?:=([^;]+))?;?\s*?#', $value, $matches)) {
            $data['Name'] = array_shift($matches[1]);
            $data['Value'] = array_shift($matches[2]);

            if ($matches[1] && $matches[2]) {
                foreach ($this->getCookieDefaults() as $key => $value) {
                    foreach ($matches[1] as $index => $val) {
                        if (!strcasecmp($key, $val)) {
                            if (in_array($key, array('Secure', 'Discard', 'HttpOnly'))) {
                                $data[$key] = true;
                            } else {
                                $data[$key] = $matches[2][$index];
                            }
                        }
                    }
                }
            }
        }

        return $data;
    }

    /**
     * Determine if a data is valid for cookie.
     *
     * @param array $data
     *
     * @return boolean
     */
    protected function isCookieData(array $data)
    {
        return !empty($data['Name']) && isset($data['Value']);
    }

    /**
     * Check if the cookie matches a path value.
     *
     * @param string $path Path to check against
     *
     * @return bool
     */
    protected function isCookieMatchesPath(array $cookie, $path)
    {
        return empty($cookie['Path']) || strpos($path, $cookie['Path']) === 0;
    }

    /**
     * Check if the cookie matches a domain value.
     *
     * @param string $domain Domain to check against
     *
     * @return bool
     */
    protected function isCookieMatchesDomain(array $cookie, $domain)
    {
        // Remove the leading '.' as per spec in RFC 6265.
        // http://tools.ietf.org/html/rfc6265#section-5.2.3
        $cookieDomain = isset($cookie['Domain']) ? ltrim($cookie['Domain'], '.') : null;

        // Domain not set or exact match.
        if (!$cookieDomain || !strcasecmp($domain, $cookieDomain)) {
            return true;
        }

        // Matching the subdomain according to RFC 6265.
        // http://tools.ietf.org/html/rfc6265#section-5.1.3
        if (filter_var($domain, FILTER_VALIDATE_IP)) {
            return false;
        }

        return (bool) preg_match('/\.'.preg_quote($cookieDomain).'$/i', $domain);
    }

    /**
     * Create a cookie string from array.
     *
     * @param array   $data
     * @param boolean $fully
     *
     * @return string
     */
    protected function getCookieAsString(array $cookie, $fully = false)
    {
        $str = $cookie['Name'].'='.$cookie['Value'].'; ';
        if (!$fully) {
            return $str;
        }

        // ensure that the cookie have all attributes.
        $cookie += $this->getCookieDefaults();

        foreach ($cookie as $key => $value) {
            if ($key != 'Name' && $key != 'Value' && $value !== null && $value !== false) {
                if ($key == 'Expires') {
                    $str .= 'Expires='.gmdate('D, d M Y H:i:s \G\M\T', $value).'; ';
                } else {
                    $str .= ($value === true ? $key : "{$key}={$value}").'; ';
                }
            }
        }

        return rtrim($str, '; ');
    }

    /**
     * Gets field headers.
     *
     * @param string $boundary
     * @param array  $headers
     *
     * @return string
     */
    protected function getMultipartHeaders($boundary, array $headers)
    {
        $header = '';
        foreach ($headers as $name => $value) {
            $header .= sprintf("%s: %s\r\n", $name, $value);
        }

        return  "--{$boundary}\r\n".$header."\r\n";
    }

    /**
     * Gets multipart data as string.
     *
     * @param string $boundary
     * @param array  $parts
     *
     * @return string
     */
    protected function getMultipartAsString($boundary, $parts)
    {
        $out = '';
        foreach ($parts as $field) {
            $field += array('filename' => null, 'headers' => array());

            $headers = $field['headers'];
            $headers['Content-Disposition'] = 'form-data; name="'.$field['name'].'"'
                    .($field['filename'] ? '; filename="'.$field['filename'].'"' : '');
            $out .= $this->getMultipartHeaders($boundary, $headers);
            $out .= $this->getBodyAsString($field['contents']);
            $out .= "\r\n";
        }
        $out .= "--{$boundary}--\r\n";

        return $out;
    }

    /**
     * Gets body as string.
     *
     * @param string|resource $body
     * @param boolean         $close Close stream if body is resource.
     *
     * @return string
     */
    protected function getBodyAsString($body, $close = true)
    {
        $out = '';
        if (is_resource($body)) {
            $out = stream_get_contents($body);
            $close && fclose($body);
        } else {
            $out = $body;
        }

        return $out;
    }

    /**
     * Returns type of given file path.
     *
     * @param string $filePath
     *
     * @return string
     */
    protected function getFileType($filePath)
    {
        $filename = realpath($filePath);
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        if (preg_match('/^(?:jpe?g|png|[gt]if|bmp|swf)$/', $extension)) {
            $file = getimagesize($filename);

            if (isset($file['mime'])) {
                return $file['mime'];
            }
        }
        if (class_exists('finfo', false)) {
            if ($info = new finfo(defined('FILEINFO_MIME_TYPE') ? FILEINFO_MIME_TYPE : FILEINFO_MIME)) {
                return $info->file($filename);
            }
        }
        if (ini_get('mime_magic.magicfile') && function_exists('mime_content_type')) {
            return mime_content_type($filename);
        }
    }

    /**
     * Get absolute url for following redirect.
     *
     * @param string $relative
     * @param string $base
     *
     * @return string
     */
    protected function getAbsoluteUrl($relative, $base)
    {
        // remove query string
        $base = preg_replace('#(\?|\#).*?$#', '', $base);
        if (parse_url($relative, PHP_URL_SCHEME) != '') {
            return $relative;
        }
        if ($relative[0] == '#' || $relative[0] == '?') {
            return $base.$relative;
        }
        extract(parse_url($base));
        $path = preg_replace('#/[^/]*$#', '', $path);

        $relative[0] == '/' && $path = '';
        $absolute = $host.$path.'/'.$relative;

        $patterns = array('#(/\.?/)#', '#/(?!\.\.)[^/]+/\.\./#');
        for ($count = 1; $count > 0; $absolute = preg_replace($patterns, '/', $absolute, -1, $count));

        return $scheme.'://'.$absolute;
    }

    /**
     * Parse request uri.
     *
     * @param string $uri
     *
     * @return array
     */
    protected function parseUri($uri)
    {
        $parts = parse_url($uri);
        $scheme = isset($parts['scheme']) ? $parts['scheme'] : '';
        $user = isset($parts['user']) ? $parts['user'] : '';
        $pass = isset($parts['pass']) ? $parts['pass'] : '';
        $host = isset($parts['host']) ? $parts['host'] : '';
        $port = isset($parts['port']) ? $parts['port'] : null;
        $path = isset($parts['path']) ? $parts['path'] : '/';
        $query = isset($parts['query']) ? $parts['query'] : '';
        $fragment = isset($parts['fragment']) ? $parts['fragment'] : '';

        return compact('scheme', 'user', 'pass', 'host', 'port', 'path', 'query', 'fragment');
    }

    /**
     * Gets uri as string.
     *
     * @param array $uri
     *
     * @return string
     */
    protected function getUriAsString(array $uri)
    {
        extract($uri);
        $userInfo = $user.($pass ? ':'.$pass : '');
        $authority = ($userInfo ? $userInfo.'@' : '').$host.($port !== null ? ':'.$port : '');

        if ($authority && substr($path, 0, 1) === '/') {
            $path = '/'.ltrim($path, '/');
        }
        if (!$authority && substr($path, 0, 2) === '//') {
            $path = '/'.ltrim($path, '/');
        }

        return ($scheme ? $scheme.':' : '')
            .($authority ? '//'.$authority : '')
            .$path
            .($query ? '?'.$query : '')
            .($fragment ? '#'.$fragment : '');
    }

    /**
     * Gets handler name.
     *
     * @return string
     */
    protected function getHandler()
    {
        static $available;
        if ($available === null) {
            $available = array(
                'socket' => function_exists('fsockopen') && function_exists('ini_get') && ini_get('allow_url_fopen'),
                'curl'   => function_exists('curl_init'),
            );
        }

        if ($this->options['handler'] !== null) {
            if (empty($available[$this->options['handler']])) {
                throw new Exception(sprintf('Handler "%s" is not available.'));
            }

            return $this->options['handler'];
        }

        if ($available['curl']) {
            return 'curl';
        }

        if ($available['socket'] && $this->options['proxy_type'] != 'sock5') {
            return 'socket';
        }

        throw new Exception('Have no available handler based on your request options/ PHP config.');
    }
}