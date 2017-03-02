import hashlib
import hmac
import os
import random
import re
from string import letters
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# the below function are used for hashing passwords and username

SECRET = 'adarsh'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(val):
    return '%s|%s' % (val, hash_str(val))
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# the bloghandler function contains rendering function to display page content
# this function also contains for user login and setting cookies


class BlogHandler(webapp2.RequestHandler):
        def write(self, *a, **kw):
            self.response.out.write(*a, **kw)

        def render_str(self, template, **params):
            params['user'] = self.user
            return render_str(template, **params)

        def render(self, template, **kw):
            self.write(self.render_str(template, **kw))

        def set_secure_cookie(self, name, val):
            cookie_val = make_secure_val(val)
            self.response.headers.add_header(
              'Set-Cookie',
              '%s=%s; Path=/' % (name, cookie_val))

        def read_secure_cookie(self, name):
            cookie_val = self.request.cookies.get(name)
            return cookie_val and check_secure_val(cookie_val)

        def login(self, user):
            self.set_secure_cookie('user_id', str(user.key().id()))

        def logout(self):
            self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

        def initialize(self, *a, **kw):
            webapp2.RequestHandler.initialize(self, *a, **kw)
            uid = self.read_secure_cookie('user_id')
            self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
        def get(self):
            self.write('Hello, Udacity!')

# below functions are used for hashing passwords to improve security


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# Below is the user object that stores user information


class User(db.Model):
        name = db.StringProperty(required=True)
        pw_hash = db.StringProperty(required=True)
        email = db.StringProperty()

        @classmethod
        def by_id(cls, uid):
            return cls.get_by_id(uid, parent=users_key())

        @classmethod
        def by_name(cls, name):
            # u = db.GqlQuery("SELECT * FROM User WHERE name = :1", name)
            u = User.all().filter('name =', name).get()
            return u

        @classmethod
        def register(cls, name, pw, email=None):
            pw_hash = make_pw_hash(name, pw)
            return cls(parent=users_key(), name=name,
                       pw_hash=pw_hash, email=email)

        @classmethod
        def login(cls, name, pw):
            u = cls.by_name(name)
            if u and valid_pw(name, pw, u.pw_hash):
                return u

# User Signup, this class collects user information before registering a user


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# the register function stores user information from signup form in user obj

class Register(Signup):
        def done(self):
            u = User.by_name(self.username)
            if u:
                msg = "That user already exist."
                self.render('signup-form.html', error_username=msg)
            else:
                u = User.register(self.username, self.password, self.email)
                print " name ===", self.username
                u.put()
                self.login(u)
                self.redirect('/blog')

# the below class contains the login funciton and collects user login info


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/unit3/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class WelcomePage(BlogHandler):
        def get(self):
            if self.user:
                self.render('welcome.html', username=self.user.name)
            else:
                self.redirect('/signup')

# below function deletes the user cookie in order to logout the user


class Logout(BlogHandler):
        def get(self):
            self.logout()
            self.redirect('/blog')
# below is the model for a new post object is used for storing posts


class Post(db.Model):
        subject = db.StringProperty(required=True)
        content = db.TextProperty(required=True)
        created = db.DateTimeProperty(auto_now_add=True)
        author = db.TextProperty()
        liked_by = db.ListProperty(str)
        last_modified = db.DateTimeProperty(auto_now=True)

        def render(self):
            self._render_text = self.content.replace('\n', '<br>')
            return render_str("post.html", p=self)

# below class is the model for comments objects that stores user comments


class Comment(db.Model):
        comment = db.StringProperty(required=True)
        cAuthor = db.StringProperty(required=True)
        created = db.DateTimeProperty(auto_now_add=True)
        post = db.ReferenceProperty(Post, collection_name='comments')

#   below classes handles the error that occurs when liking the posts


class likeError(BlogHandler):
        def get(self):
            self.write('You can only like a post once.')


class likeUserErr(BlogHandler):
        def get(self):
            self.write('You cannot like a post that you have created!!!')


class LikePost(db.Model):
        postid = db.IntegerProperty(required=True)
        post = db.ReferenceProperty(Post, collection_name='Likes')


# below class handles user post likes and it stores the likes in a like object

class like(BlogHandler):
        def get(self, post_id):
            if not self.user:
                    self.redirect('/login')
            else:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                lAuthor = post.author
                currentUser = self.user.name
                if(lAuthor == currentUser):
                    self.redirect('/likeUErr')
                elif (currentUser in post.liked_by):
                        self.redirect('/Lerror')
                else:
                    post.liked_by.append(currentUser)
                    post.put()
                    l = LikePost(postid=int(post_id), post=post.key(),
                                 parent=blog_key())
                    l.put()
                    self.redirect('/blog')

# below class handles the comments post by users


class newComment(BlogHandler):
        def get(self, post_id):
            if not self.user:
                return self.redirect('/login')
            else:
                    key = db.Key.from_path('Post', int(post_id),
                                           parent=blog_key())
                    post = db.get(key)
                    subject = post.subject
                    content = post.content
                    self.render("newcomment.html", subject=subject,
                                content=content)

        def post(self, post_id):
            if not self.user:
                return self.redirect('/login')
            else:
                    key = db.Key.from_path('Post', int(post_id),
                                           parent=blog_key())
                    post = db.get(key)
                    comment = self.request.get('comment')
                    if comment:
                        c = Comment(comment=comment,
                                    cAuthor=User.by_name(self.user.name).name,
                                    post=post.key(), parent=blog_key())
                        c.put()
                        self.redirect('/blog/%s' % str(post_id))
                    else:
                            error = "please enter a comment"
                            self.render("newcomment.html", comment=comment,
                                        error=error)

# below class handles the comment updates by users


class UpdateComment(BlogHandler):
    def get(self, post_id, comment_id):
        if not self.user:
            return self.redirect('/login')
        else:
            post = Post.get_by_id(int(post_id), parent=blog_key())
            comment = Comment.get_by_id(int(comment_id), parent=blog_key())
            if not comment:
                self.error(404)
                return
            if (comment.cAuthor == self.user.name):
                error = ""
                self.render("updatecomment.html", subject=post.subject,
                            content=post.content, error=error,
                            comment=comment.comment, p=post)
            else:
                    self.redirect('/commenterror')

    def post(self, post_id, comment_id):
        if not self.user:
            return self.redirect('/login')
        else:
            ucomment = self.request.get('comment')
            if ucomment:
                post = Post.get_by_id(int(post_id), parent=blog_key())
                comment = Comment.get_by_id(int(comment_id), parent=blog_key())
                if not comment:
                    self.error(404)
                    return
                if (comment.cAuthor == self.user.name):
                        comment.comment = ucomment
                        comment.put()
                        self.redirect('/blog/%s' % str(post_id))
                else:
                        self.redirect('/commenterror')
            else:
                        post = Post.get_by_id(int(post_id), parent=blog_key())
                        error = "please enter the comment!"
                        self.render("updatecomment.html", subject=post.subject,
                                    content=post.content, error=error, p=post)
# below class deletes the comment posted by user


class deleteComment(BlogHandler):
        def get(self, post_id, comment_id):
            if not self.user:
                return self.redirect('/login')
            else:
                post = Post.get_by_id(int(post_id), parent=blog_key())
                comment = Comment.get_by_id(int(comment_id), parent=blog_key())
                if not comment:
                    self.error(404)
                    return
                elif (comment.cAuthor == self.user.name):
                        comment.delete()
                        self.redirect('/blog/%s' % str(post_id))
                else:
                    self.redirect('/commenterror')

# below class handles the error when posting the comment


class CommentError(BlogHandler):
    def get(self):
        self.write('You can only edit or delete comments you have created.')

# below class handles the new post submitted by the user


class NewPost(BlogHandler):
    def get(self):
        if not self.user:
            return self.redirect('/login')
        else:
            self.render('newpost.html')

    def post(self):
        if not self.user:
            return self.redirect('/login')
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            p = Post(subject=subject, content=content,
                     author=User.by_name(self.user.name).name,
                     liked_by=[], parent=blog_key())
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)

# below class handles the rendering of each post submitted by the user


class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select*from Post order by created desc limit 10")
        self.render('front.html', posts=posts)

# below class is used for displaying a specific post


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post)

# below class handles the post updates by the user


class updatePost(BlogHandler):
        def get(self, post_id):
            if not self.user:
                return self.redirect('/login')
            else:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                if not post:
                    self.error(404)
                    return
                if (post.author == self.user.name):
                    error = ""
                    self.render("updatepost.html", subject=post.subject,
                                content=post.content, error=error)
                else:
                    self.redirect('/editDeleteError')

        def post(self, post_id):
            if not self.user:
                return self.redirect('/login')
            else:
                subject = self.request.get('subject')
                content = self.request.get('content')
                if subject and content:
                    key = db.Key.from_path('Post', int(post_id),
                                           parent=blog_key())
                    uPost = db.get(key)
                    if not uPost:
                        self.error(404)
                        return
                    uPost.subject = subject
                    uPost.content = content
                    uPost.put()
                    self.redirect('/blog/%s' % str(uPost.key().id()))
                else:
                    error = "subject and content, please!"
                    self.render("newpost.html", subject=subject,
                                content=content, error=error)
# below class handles the deleting of posts by users


class DeletePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if (post.author == self.user.name):
                post.delete()
                self.render("deletepost.html")
            else:
                self.redirect('/editDeleteError')

# below class handles the error that occurs when updating or deleting posts


class editDeleteError(BlogHandler):
    def get(self):
        self.write('You are not authorized to edit or delete this post.')
app = webapp2.WSGIApplication([('/', BlogFront),
                              ('/blog/?', BlogFront),
                              ('/blog/delete/([0-9]+)', DeletePost),
                              ('/blog/([0-9]+)', PostPage),
                              ('/updatepost/([0-9]+)', updatePost),
                              ('/blog/([0-9]+)/updatecomment/([0-9]+)',
                               UpdateComment),
                              ('/blog/([0-9]+)/deletecomment/([0-9]+)',
                               deleteComment),
                              ('/commenterror', CommentError),
                              ('/editDeleteError', editDeleteError),
                              ('/likeUErr', likeUserErr),
                              ('/signup', Register),
                              ('/login', Login),
                              ('/Lerror', likeError),
                              ('/comment/([0-9]+)', newComment),
                              ('/blog/([0-9]+)/likes', like),
                              ('/logout', Logout),
                              ('/unit3/welcome', WelcomePage),
                              ('/blog/newpost', NewPost), ], debug=True)










