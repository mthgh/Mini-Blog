import re
import hmac
import hashlib
import random
import string
from xml.dom import minidom
import urllib2

ip_key = "secret"  # please create your own
map_key = "secret" # please create your own
SECRET = 'secret' # please create your own

# check_user, check_pas, check_email: check if the user sign up info is valid or not

def check_user(username):
    pattern = re.compile(r"^[a-zA-Z0-9_.-]{3,20}$")
    if pattern.match(username):
        return True

def check_pas(password):
    pattern = re.compile(r"^.{3,20}$")
    if pattern.match(password):
        return True

def check_email(email):
    pattern = re.compile(r"(^[\S]+@[\S]+\.[\S]+$)")
    if pattern.match(email) or not email:
        return True
    
# hash_pw, verify_pw: hash the password from signup page to db and check password match from login

def hash_pw(username, password, salt=''):
    if not salt:
        salt = ''.join([random.choice(string.ascii_letters) for i in range(0,16)])
    h = hmac.new(salt, username+password, hashlib.sha256).hexdigest()
    return "%s|%s" % (salt,h)

def verify_pw(h, username, password):
    salt = h.split('|')[0]
    return h == hash_pw(username, password, salt)
 
# cookie_val, get_cookie: set user cookie on website and check if user cookie is valid or not

def cookie_val(username):
    h = hmac.new(SECRET,username).hexdigest()
    return "%s|%s" % (username, h)

def get_cookie(h):
    username= h.split("|")[0]
    if cookie_val(username) == h:
        return username

def ip_to_coord(ip):
    url = "http://api.ipinfodb.com/v3/ip-city/?key=%s&ip=%s&format=xml" %(ip_key, ip)
    try:
        content = urllib2.urlopen(url).read()
    except:
        'URLError'
        return
    if content:
        xml_file = minidom.parseString(content)
        lat =  xml_file.getElementsByTagName('latitude')[0].childNodes[0].nodeValue
        lon = xml_file.getElementsByTagName('longitude')[0].childNodes[0].nodeValue
        if int(float(lat)) and int(float(lon)):
            return lat,lon

def map_graph(all_user):
    markers=''
    for e in all_user:
        if e.coord:
            markers = markers + "&markers=%7Clabel:S%7C" + str(e.coord)
    map_url = "https://maps.googleapis.com/maps/api/staticmap?size=500x400%s&key=%s"%(markers, map_key)
    return map_url

def make_obj(blog):
    dic = {'title':blog.title,
           'content':blog.content,
           'created':blog.created.strftime('%c'),
           'last_modified':blog.last_modified.strftime('%c')
           }
    return dic
    
    
    

