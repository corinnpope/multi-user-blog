# import pdb
# pdb.set_trace()


import os
import re
from string import letters
import time
import random
import hashlib
import hmac

import webapp2
import jinja2


from urlparse import urlparse

from google.appengine.ext import db

# setup jinja
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'udacity_full_stack'

# fix "nameError: global name 'render_str' is not defined"
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# make sure user & cookie values match
def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	# split the secure val at the pipe and make sure they're the same
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

# make things secure
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_password_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

#  make sure pw hash is same as hash
def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_password_hash(name, password, salt)

# ######users and blog key
def users_key(group ='default'):
	return db.Key.from_path('users', group)

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)




# ############Database: Users##########################

class User(db.Model):
	name = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)

	@classmethod
	def get_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def get_name(cls, name):
		# return User.all().filter('name =', name).get()
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw):
		password_hash = make_password_hash(name, pw)
		return User(parent = users_key(),
			name = name, 
			password_hash = password_hash)

	@classmethod
	def login(cls, name, pw):
		u = cls.get_name(name)
		if u and valid_pw(name, pw, u.password_hash):
			return u

# #################################################################

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	# Do Cookie Monster Stuff
	def set_cookie(self, name, val):
		cookie_value = make_secure_val(val)
		#set and expiration time 2 weeks from now
		# expires = time.time() + 14 * 24 * 3600
		# strftime("%b %d, %Y", expires)
		self.response.headers.add_header(
			# 'Set-Cookie',
			# '%s=%s; Path=/' % (name, cookie_value),
			# 'Max-Age = 14')
			            'Set-Cookie',
            			'%s=%s; Path=/' % (name, cookie_value))

	def read_cookie(self, name):
		cookie_value = self.request.cookies.get(name)
		return cookie_value and check_secure_val(cookie_value)

	# ############login/logout/initialize ###################
	def login(self, user):
		self.set_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_cookie('user_id')
		self.user = uid and User.get_id(int(uid))

# #########Posts #########

class Post(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	# add author property
	# set to required later
	author = db.StringProperty(required = False)
	# TODO: add tags property?? 
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('/n', '<br>')
		return render_str("post.html", p = self)

	# def get_post_id(self):
	# 	return p.key().id()

	# def get_author(self):
	#  	return p.key().author()

# GAHHHHHHHHH
class HomePage(BlogHandler):
	def get(self):

		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
		if self.user:
			self.render('home.html', posts = posts, username = self.user.name)
		else:
			self.render("home.html", posts = posts)

# ################################

class PostPage(BlogHandler):
	def get(self, post_id):
		# convert post id to an int
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post, username = self.user.name)

class NewPost(BlogHandler):
	def get(self):
		if self.user:
			self.render("new_post.html", username = self.user.name)
		else:
			self.render("login.html")

	def post(self):
		title = self.request.get('title')
		content = self.request.get('content')
		author = self.user.name

		if title and content:
			# store to db if title and content are there
			p = Post(parent = blog_key(), title = title, content = content, author = author)
			p.put()
			self.redirect('/%s' % str(p.key().id()))

		else:
			error = "title and text are required"
			self.render("new_post.html", title = title, content = content, author = author, error = error)

class EditPost(BlogHandler):
	def get(self, post_id):

		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if self.user.name == post.author:
			self.render('edit_post.html', post = post)
		else:
			self.render("login.html")


	def post(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)

			post.title = self.request.get('title')
			post.content = self.request.get('content')

			post.put()
			# otherwise updating lags
			time.sleep(0.1)
			self.redirect('/')
		else:
			self.redirect('/login.html')




# ######### User Signup and Confirmation/Save ###########

# Check for valid username and password values
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)


class Signup(BlogHandler):
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False
		# why do these need self while other post methods don't??
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.confirm_password = self.request.get('confirm_password')

		params = dict(username = self.username)

		# make sure everything is valid, if it is, go to 'done' method
		# if not valid_username(self.username):
		# 	params['error_username'] = "That's not a valid username"
		# 	have_error = True

		# if not valid_password(self.password):
		# 	params['error_password'] = "That's not a valid password"
		# 	have_error = True
		# elif self.password != self.confirm_password:
		# 	params['error_confirm_password'] = "Passwords don't match"
		# 	have_error = True
		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True
		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.confirm_password:
			params['error_confirm_password'] = "Your passwords didn't match."
			have_error = True

		if have_error:
			self.render('signup.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError

class SaveUser(Signup):
	def done(self):
		# check to see if user exists
		u = User.get_name(self.username)
		if u:
			msg = "Username taken"
			self.render('signup.html', error_username = msg)
		else:
			u = User.register(self.username, self.password)
			u.put()

			self.login(u)
			self.redirect('/')

#  ###############Login/Logout #####################

class LogIn(BlogHandler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)

		if u:
			self.login(u)
			self.redirect('/')
		else:
			msg = 'That is not a valid username or password'
			self.render('login.html', error = msg)

class LogOut(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/')

app = webapp2.WSGIApplication([('/', HomePage),
								('/([0-9]+)', PostPage),
								('/new_post', NewPost),
								('/?', HomePage),
								('/login', LogIn),
								('/logout', LogOut),
								('/signup', SaveUser),
								('/edit_post/(\d+)', EditPost)
								],
								debug = True)