import jinja2
import webapp2
import os
import func
import logging
import re
import json

from google.appengine.ext import db
from google.appengine.api import memcache

temp_dir=os.path.join(os.path.dirname(__file__),'template')
jinja_env=jinja2.Environment(loader = jinja2.FileSystemLoader(temp_dir),
                             autoescape = True)

# db_users

def users_key(group='default'):
    return db.Key.from_path('UserInfo', group)

class UserInfo(db.Model):
    user = db.StringProperty(required=True)
    pw = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)
    coord = db.GeoPtProperty(required=False)

    @classmethod
    def by_id(cls, uid):
        return UserInfo.get_by_id(uid, parent = users_key())

    @classmethod
    def by_user(cls, username):
        return UserInfo.all().filter('user =', username).get()

    @classmethod
    def regist(cls, username, pw, email):
        e = UserInfo(user = username,
                     pw = func.hash_pw(username,pw),
                     email = email,
                     parent=users_key())       
        e.put()
        return e
    
# db_blog
    
def blog_key(uid):
    return db.Key.from_path('Blog', uid)

class Blog(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_uid(cls, uid):
        return Blog.all().ancestor(blog_key(uid)).order('-created')

    @classmethod
    def by_uid_front(cls, uid):
        return Blog.all().ancestor(blog_key(uid)).order('-created').run(limit=10)

    @classmethod
    def by_uid_bid(cls, uid, bid):
        return Blog.get_by_id(bid, parent = blog_key(uid))

    @classmethod
    def all_blog(cls):
        return Blog.all().order('-created')

    @classmethod
    def del_blog(cls, uid, bid):
        blog = Blog.by_uid_bid(uid,bid)
        blog.delete()

    @classmethod
    def regist(cls, title, content,uid):
        e = Blog(title=title,
                 content=content,
                 parent=blog_key(uid))
        return e
    

# cache db queries
class Cache():
    @classmethod
    def get(cls, key):
        return memcache.get(key)

    @classmethod
    def sets(cls, key, value):
        result = memcache.set(key, value)
        if result:
            logging.error('set cache successfully')
        return Cache.get(key)

    @classmethod
    def uname_user(cls, username, update=False):
        key = 'uname_'+username
        if not Cache.get(key) or update:
            q = UserInfo.by_user(username)
            if q:
                Cache.sets(key, q)
        return Cache.get(key)

    @classmethod
    def uid_user(cls, uid, update=False):
        key = 'uid_'+uid
        if not Cache.get(key) or update:
            q = UserInfo.by_id(int(uid))
            if q:
                Cache.sets(key, q)
        return Cache.get(key)

    @classmethod
    def alluser(cls, update=False):
        key = 'users'
        if not Cache.get(key) or update:
            q = UserInfo.all()
            Cache.sets(key, q)
        return Cache.get(key)

    @classmethod
    def allblogs(cls, update=False):
        key = 'blogs'
        if not Cache.get(key) or update:
            q = Blog.all_blog()
            Cache.sets(key, q)
        return Cache.get(key)

    @classmethod
    def uid_blogs(cls, uid, update=False):
        key = 'blogs'+ uid
        if not Cache.get(key) or update:
            q = Blog.by_uid(uid)
            Cache.sets(key, q)
        return Cache.get(key)
    
    @classmethod
    def uid_bid_blog(cls, uid, bid, update=False):
        key = uid + bid
        if not Cache.get(key) or update:
            q = Blog.by_uid_bid(uid, int(bid))
            if q:
                Cache.sets(key, q)
        return Cache.get(key)

#basichandler containing helping functions

class BasicHandler(webapp2.RequestHandler):
    def render_str(self, template,**params):
        temp = jinja_env.get_template(template)
        return temp.render(params)
    
    def render(self, template, **params):
        return self.response.write(self.render_str(template, **params))

    def write(self,*a,**kw):
        return self.response.write(*a,**kw)

    def sets_cookie(self, username=''):
        if username:
            return self.response.set_cookie("user",value="%s"%(func.cookie_val(username)),path="/")
        else:
            return self.response.set_cookie("user",value='',path='/')
    
    def user_cookie(self):
        h = self.request.cookies.get('user')
        if h:
            username = func.get_cookie(h)
            if username:
                return username

    # the following function determine which page to render, depending on if there is cookie or not
           
    def which_page(self,redi_page,temp,**params):
        username = self.user_cookie()
        if username:
            self.redirect(redi_page)
        else:
            self.render(temp, **params)

    def if_user(self):
        username = self.user_cookie()
        userid = None
        if username:
            #q = UserInfo.by_user(username)
            q = Cache.uname_user(username)
            if q:
                userid = q.key().id()
        return username, userid

    # the following function determine whether to render or get error
    def error_or_render(self, test, temp, **params):
        if test:
            self.render(temp, **params)
        else:
            self.error(404)

    def blog_disp(self, userid, page):
        blogs = ''
        if page.isdigit():
            #q = Blog.by_uid_bid(userid, int(page))
            q = Cache.uid_bid_blog(userid, page)
            if q:
                blogs=[q]
            else:
                blogs='error'
        if page == 'front':
            #blogs = Blog.by_uid_front(userid)
            blogs = Cache.uid_blogs(userid).run(limit=10)
        if page == 'allblog':
            #blogs = Blog.by_uid(userid)
            blogs = Cache.uid_blogs(userid)
        return blogs

    def output_js(self, result):
        self.response.headers["Content_Type"] = "application/json:charset-UTF-8"
        js = json.dumps(result)
        self.write(js)

class Welcome(BasicHandler):
    def get(self):
        #all_user = UserInfo.all()
        all_user = Cache.alluser()
        map_url = func.map_graph(all_user)
        username, userid = self.if_user()
        self.render('main.html', username=username, 
                                 userid=userid,
                                 map_url=map_url)

class Signup(BasicHandler):
    def get(self):
        self.which_page('/', 'signup.html')
        
    def post(self, error1='', error2='', error3='', error4=''):
        username=self.request.get('username')
        password=self.request.get('password')
        verify=self.request.get('verify')
        email=self.request.get('email')

        #user_exist = UserInfo.by_user(username)
        user_exist = Cache.uname_user(username)

        if user_exist:
            self.render('signup.html', error1='This username already exits')
            
        else:
            check_user = func.check_user(username)
            check_pas = func.check_pas(password)
            check_email = func.check_email(email)

            if check_user and check_pas and check_email and verify==password:
                user = UserInfo.regist(username, password, email)
                
                ip = self.request.remote_addr
                if func.ip_to_coord(ip):
                    lat,lon = func.ip_to_coord(ip)
                    coord = db.GeoPt(lat,lon)
                    user.coord = coord
                    user.put()
                    
                Cache.alluser(update=True)
                self.sets_cookie(username)
                self.redirect('/')
            else:
                if not check_user:
                    error1='Please input a valid username'
                if not check_pas:
                    error2='Please input a valid password'
                if not check_email:
                    error4='Please input a valid email'
                if check_pas and verify!=password:
                    error3='Password does not match'
                self.render('signup.html', error1=error1,
                                           error2=error2,
                                           error3=error3,
                                           error4=error4,
                                           username=username,
                                           email=email)

class Login(BasicHandler):
    def get(self):
        self.which_page('/','login.html')
        
    def post(self, error1='', error2='', error=''):
        username = self.request.get('username')
        password = self.request.get('password')
        #q = UserInfo.by_user(username)
        q = Cache.uname_user(username)
        
        if q and func.verify_pw(str(q.pw), username, password):
            self.sets_cookie(username)
            self.redirect('/')
        else:
            if not username:
                error1='please input a username'
            if not password:
                error2='please input a password'
            else:
                error='wrong username or password'
            self.render('login.html', username=username,
                                      error1=error1,
                                      error2=error2,
                                      error=error,)
       

class Newpost(BasicHandler):
    def get(self, userid, blog_id=''):
        username,db_uid = self.if_user()
        if username and db_uid == int(userid):
            title = ''
            content = ''
            if blog_id:
                #blog = Blog.by_uid_bid(userid, int(blog_id))
                blog = Cache.uid_bid_blog(userid, blog_id)
                if blog:
                    title = blog.title
                    content = blog.content
                else:
                    self.error(404)
                    return 
            self.render('newpost.html', username=username,
                                        userid=userid,
                                        title=title,
                                        content=content)
        else:
            self.redirect('/')
            
    def post(self, userid, blog_id=''):
        title = self.request.get('title')
        content = self.request.get('content')
        if blog_id:
            #blog = Blog.by_uid_bid(userid, int(blog_id))
            blog = Cache.uid_bid_blog(userid, blog_id)
        else:
            blog = Blog.regist('default', 'default',userid)

        if title and content:
            blog.title = title
            blog.content = content
            blog.put()
            Cache.allblogs(update=True)
            Cache.uid_blogs(userid,update=True)
            Cache.uid_bid_blog(userid, str(blog.key().id()), update=True)
            self.redirect('/%s/%s'%(userid, str(blog.key().id())))
        else:
            error = 'Please input both title and content'
            self.render('newpost.html', error=error,
                                        title=title,
                                        content=content)

class BlogDisp(BasicHandler):
    def get(self, userid, page):
        username = self.user_cookie()
        #u_info = UserInfo.by_id(int(userid))
        u_info = Cache.uid_user(userid)
        blogs = self.blog_disp(userid, page)
        path=self.request.path

        if path.endswith('.json'):
            value = [func.make_obj(blog) for blog in blogs]
            result = dict([(u_info.user, value)])
            self.output_js(result)
        else:
            self.error_or_render(u_info, 'blog_disp.html', blogs=blogs,
                                                           u_info=u_info,
                                                           userid=userid,
                                                           username=username,
                                                           page=page)
        
    def post(self, userid, page):
        blog_id = self.request.get('blog_id')
        Blog.del_blog(userid, int(blog_id))
        Cache.allblogs(update=True)
        Cache.uid_blogs(userid,update=True)
        Cache.uid_bid_blog(userid, blog_id, update=True)
        if page == 'allblog':
            self.redirect('/%s/allblog'%(userid))
        else:
            self.redirect('/%s/front'%(userid))
            

class Logout(BasicHandler):
    def get(self, userid):
        username,db_uid = self.if_user()
        if username and db_uid == int(userid):
            self.sets_cookie()
        self.redirect('/')

class UserDisp(BasicHandler):
    def get(self):
        path = self.request.path
        username, userid = self.if_user()
        #blogs = Blog.all_blog()
        blogs = Cache.allblogs(update=True)
        if path.endswith('.json'):
            result ={}
            for blog in blogs:
                b_userid = blog.key().parent().name()
                b_user = Cache.uid_user(b_userid).user
                if b_user in result:
                    result[b_user].append(func.make_obj(blog))
                else:
                    result[b_user]=[func.make_obj(blog)]
            self.output_js(result)
        else:
            self.render('blog_disp.html', blogs=blogs,
                                         username=username,
                                         userid=userid)

class UserSetting(BasicHandler):
    def get(self, userid, page):
        username,db_uid = self.if_user()
        if username and db_uid == int(userid):
            u_info = Cache.uname_user(username)
            #u_info = UserInfo.by_user(username)
            if page=='setting':
                temp = 'setting.html'
            if page=='user_update':
                temp = 'user_update.html'
            self.render(temp, u_info=u_info,
                              userid=userid)
        else:
            self.redirect('/')

    def post(self,userid, page, error='', error1='', error2='', error3='', error4=''):
        #u_info = UserInfo.by_id(int(userid))
        u_info = Cache.uid_user(userid)
        
        if page=='setting':
            #u_blogs = Blog.by_uid(userid)
            u_blogs = Cache.uid_blogs(userid)
            
            u_info.delete()
            memcache.delete('uname_'+u_info.user)
            memcache.delete('uid_'+userid)
            Cache.alluser(update=True)
            
            for blog in u_blogs:
                blog.delete()
                memcache.delete(userid+str(blog.key().id()))
            Cache.allblogs(update=True)
            memcache.delete('blogs'+userid)
            
            self.sets_cookie()
            self.redirect('/')
            
        if page=='user_update':
            o_pw = self.request.get('o_pw')
            n_pw = self.request.get('n_pw')
            verify = self.request.get('verify')
            email = self.request.get('email')
            err = False
            update_e = False
            update_p = False

            if email==u_info.email and not n_pw:
                error = 'Please input updates'
                err = True

            if email!=u_info.email:
                if func.check_email(email):
                    update_e = 'email'
                else:
                    error4='Please input a valid email'
                    err = True
                    
            if n_pw:
                if not o_pw:
                    error1='Please input your current password'
                    err = True

                elif not func.verify_pw(str(u_info.pw), u_info.user, o_pw):
                    error1='Your password is not correct'
                    err = True

                elif not func.check_pas(n_pw):
                    error2 = 'Please input a valid password'
                    err = True

                elif n_pw != verify:
                    error3 = 'Password does not match'
                    err = True
                    
                else:
                    update_p = 'pw'
                
            if not err:
                if update_e == 'email':
                    u_info.email = email
                if update_p == 'pw':
                    u_info.pw = func.hash_pw(u_info.user,n_pw)
                u_info.put()
                Cache.uname_user(u_info.user, update=True)
                Cache.uid_user(userid, update=True)
                Cache.alluser(update=True)
                self.redirect('/%s/setting' %(userid))
                
            if err:
                self.render('user_update.html', u_info=u_info,
                                                userid=userid,
                                                error=error,
                                                error1=error1,
                                                error2=error2,
                                                error3=error3,
                                                error4=error4)
        

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/', Welcome),
                               ('/login', Login),
                               ('/([0-9]+)/newpost', Newpost),
                               ('/([0-9]+)/(front|allblog|[0-9]+)(?:.json)?', BlogDisp),
                               ('/([0-9]+)/logout',Logout),
                               ('/users(?:.json)?',UserDisp),
                               ('/([0-9]+)/(setting|user_update)', UserSetting),
                               ('/([0-9]+)/([0-9]+)/edit', Newpost),
                               ],debug=True)


