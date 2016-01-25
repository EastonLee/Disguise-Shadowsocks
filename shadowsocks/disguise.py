#coding=utf-8
__author__ = 'easton'
import unittest, os, random, string, re

def id_generator(size=10, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

'''
in shadowsocks, sometimes multiple small packages are sent, but one big packages received
so, the regular expression in the extraction should not start in the beginning(^)
'''

http_request_payload_template = \
'''POST /{0}.png HTTP/1.1\r
Host: bighouse.com\r
Connection: keep-alive\r
Pragma: no-cache\r
Cache-Control: no-cache\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r
Upgrade-Insecure-Requests: 1\r
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36\r
Content-Type: application/octet-stream\r
DNT: 1\r
Accept-Encoding: gzip, deflate\r
Accept-Language: en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4,zh-TW;q=0.2\r
\r
{1}'''

# easton: removed the tail for simplicity, now we only need to add header before the first tcp segment,
# but don't need to append tail after the last
http_responce_payload_template = '''HTTP/1.1 200 OK\r
Content-Type: image/png\r
Connection: keep-alive\r
\r
\x89PNG\r\n\x1a\xea{0}'''
#\x89PNG\r\n\x1a\xea{0}\xea\x00\x00\x00IEND\xaeB\x60\x82'''

disguise_count = 0
extract_count = 0
extract_success = 0

def replace_LF_with_CRLF(string):
    return string.replace('\n', '\r\n')

def disguise_as_http_request(data):
    global disguise_count
    disguise_count += 1
    #print 'disguising', disguise_count
    return (
        # comfirmed: '{}'.format can handle binary
        http_request_payload_template.format(id_generator(), data))

def extract_from_fake_http_request(request_str):
    """
    :type request_str: bytearray
    """
    global extract_count, extract_success
    extract_count += 1
    #to_strip = '(GET.*?previous_pic=|; \r\n\r\n)'
    to_strip = '(POST.*?q=0\.2\r\n\r\n)'
    is_disguised = False
    #'dont match the beginning'
    if re.search(to_strip, request_str, flags=re.DOTALL):
        is_disguised = True
        extract_success += 1
    striped = re.sub(to_strip, '', request_str, flags=re.DOTALL)
    return striped, is_disguised

def disguise_as_http_responce(data):
    global disguise_count
    disguise_count += 1
    return http_responce_payload_template.format(data)

def extract_from_fake_http_responce(responce_str):
    global extract_count, extract_success
    extract_count += 1
    'dont match the beginning'
    if re.search('(HTTP.*?\x89PNG\r\n\x1a\xea|\xea\x00\x00\x00IEND\xaeB\x60\x82)', responce_str, flags=re.DOTALL):
        extract_success += 1
    return str(re.sub('(HTTP.*?\x89PNG\r\n\x1a\xea|\xea\x00\x00\x00IEND\xaeB\x60\x82)', '', responce_str, flags=re.DOTALL))

class Test(unittest.TestCase):
    def est_replace_LF_with_CRLF(self):
        for i in bytearray(replace_LF_with_CRLF(http_responce_payload_template)):
            print hex(i),

    def est_disguise_as_http_request(self):
        ba = bytearray((disguise_as_http_request('\x88ciphertext\n')))
        for i in ba:
            print hex(i),
        print
        print str(ba)

    def est_disguise_as_http_responce(self):
        for i in bytearray(disguise_as_http_responce('ciphertext\n')):
            print hex(i),

    def est_extract_from_fake_http_request(self):
        print extract_from_fake_http_request(disguise_as_http_request('\x99'))

    def est_extract_from_fake_http_responce(self):
        print repr(extract_from_fake_http_responce(disguise_as_http_responce('\x99')))

    def test_bytearray_replace(self):
        ba = bytearray('get\r\n=\x98\x50\r\n')
        print repr(re.sub('(^g.*?=|\r\n$)', '', ba, flags=re.DOTALL))

    def est_str_replace(self):
        print '{}'.replace('{}', '\x41')

    def test_str_format_with_binary(self):
        print '{}'.format('\xff')

    def est_unicode_reg(self):
        print len(u'\x88aa'.encode('utf-8'))
        #print repr(re.search(u'(\x88)', u'\x88adfasdf').group(1))

if __file__ == '__main__':
    unittest.main()