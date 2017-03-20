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

def render_comment(response, comment):
	response.out.write(comment.comment)

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

# TODO add comments_key
# should this be group or name??
def comments_key(group = 'defaut'):
	return db.Key.from_path('comments', name)



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


# #########Posts #########
# must go before comment class for referenceproperty() to work
class Post(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	# add author property
	# set to required later
	author = db.StringProperty(required = False)
	like_count = db.IntegerProperty(default = 0)
	user_like = db.StringListProperty()
	# TODO: add tags property?? 
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('/n', '<br>')
		return render_str("post.html", p = self)



# Now add comments class
# referencing https://cloud.google.com/appengine/articles/modeling#one-to-many
class Comment(db.Model):
	# add required tothese later / debugging now
	posted_to = db.StringProperty(Post)
	commentor = db.StringProperty(User)
	comment = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	def render(self):
		self._render_text = self.comment.replace('/n', '<br>')
		return render_str("comment.html", c = self)

	@classmethod
	def get_comment_id(cls, commentor_id):
		return Comment.get_by_id(commentor_id, parent = comments_key())

	@classmethod
	def get_comment(cls, comment_content):
		# return User.all().filter('name =', name).get()
		c = Comment.all().filter('comment =', comment).get()
		return c


		
	# How to reference
	# class User(db.Model):
 #    name = db.StringProperty()

	# class Comment(db.Model):
	#     user = db.ReferenceProperty(User)

	# comment = db.get(comment_key)
	# user_name = comment.user.name

	# user = db.get(user_key)
	# stories_by_user = user.comment_set.get()

	# how to add
	# scott = User(name='Scott')
	# scott.put()
	# Comment(user=scott,
	#             number='(650) 555 - 2200').put()
	# Comment(user=scott,
	#             number='(650) 555 - 2201').put()


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



# #Flailing here
class LikePost(BlogHandler):
    '''Handler for Liking Posts'''
#  referenced https://discussions.udacity.com/t/stuck-on-getting-like-functionality-to-work/219359 && https://github.com/mangowolf/multi-user_blog
    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            if self.user.name != post.author:
            	# make sure user hasn't already like the post
                if self.user.name in post.user_like:
                    self.write("you can only like a post once")
                else:
                	# otherwise add the user to the list of those who liked it, increment likes, and redirect
                    post.user_like.append(self.user.name)
                    post.like_count = post.like_count + 1
                    post.put()
                    time.sleep(0.1)
                    self.redirect("/")
            if self.user.name == post.author:
                self.write("you can't like your own post!")

        else:
            self.redirect("/login")
# TODO: Write unlike handler

# GAHHHHHHHHH
class HomePage(BlogHandler):
	def get(self):

		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")
		comments = db.GqlQuery("SELECT * FROM Comment ORDER BY created DESC limit 10")
		if self.user:
			# , comments = comments
			self.render('home.html', posts = posts, username = self.user.name)
		else:
			self.render("home.html", posts = posts)

# ################################

class PostPage(BlogHandler):
	def get(self, post_id):
		# convert post id to an int
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		post_id_num = post.key().id()
		print(post_id_num)
		# comment_key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
		# comment = db.get(comment_key)
		comments = Comment.all().filter('posted_to =', str(post_id_num))
		print(comments)
		if not (post):
			self.error(404)
			return
#  comments = comments,
		self.render("permalink.html", post = post, comments = comments, username = self.user.name)

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
		user_like = []

		if title and content:
			# store to db if title and content are there
			p = Post(parent = blog_key(), title = title, content = content, author = author)
			p.put()
			# otherwise updating lags
			time.sleep(0.1)
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
			error = "you cannot edit another user's posts. please log in as the author. "
			self.render('error.html', error = error)
			# redirecting to login from error page

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
			self.redirect('/login')

class DeletePost(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent = blog_key())
		post = db.get(key)

		if self.user.name == post.author:
			self.render('delete_post.html', post = post)
		else:
			error = "you cannot delete another user's posts. please log in as the author. "
			self.render('error.html', error = error)

	def post(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)

			post.delete()
			# otherwise updating lags
			time.sleep(0.1)
			self.redirect('/')
		else:
			self.redirect('login')

# ########### Now for Comments ########################
class NewComment(BlogHandler):
	def get(self, post_id):
		post = Post.get_by_id(int(post_id), parent=blog_key())
		# key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		# post = db.get(key)
		# similar to how posts are liked
		if post is None:
		# this makes sure that the blog exists
			self.redirect('/')
		else:
			print("post id : " + post_id)
			self.render("new_comment.html", post_id = post_id)

	def post(self, post_id):
		post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		print(post_key)
		# added .id()
		post = db.get(post_key)
		print(post)
		comment = self.request.get('comment')
		print(comment)
		# commentor = self.user.name
		posted_to = str(post.key().id())
		print(posted_to)
		# check to see if post exists
		if not post:
		# if post does not exist
			return self.error(404)

		if not self.user:# checks user
			return self.redirect("/login")

		if comment:
			# store to db if title and content are there
			commentor = self.user.name
			print(commentor)
			c = Comment(parent = blog_key(), comment = comment, posted_to = posted_to, commentor = commentor)
			c.put()
			print("comment:" + c.comment)
			print("posted to:" + c.posted_to)
			print("commentor" + c.commentor)
			print('/%s' % str(post.key().id()))
			# otherwise updating lags
			time.sleep(0.1)
			# self.render('post.html', comment = comment, posted_to = posted_to, commentor = commentor)
			# self.redirect('/%s' % str(post.key().id()))
			self.redirect('/%s' % str(post.key().id()))
		else:
			error = "you must enter text"
			# TODO change to edit_comment
			self.render('%s' % str(post.key().id()), post = post, error = error)

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
		
		# parsed = urlparse.urlparse(url)
		# if urlparse.parse_qs(parsed.query)['error'] == 55:
		# 	error = "you cannot edit another user's posts. please log in as the author. "
		# 	self.render("login.html", error = error)
		# else:
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
								('/edit_post/(\d+)', EditPost), 
								('/delete_post/(\d+)', DeletePost),
								('/([0-9]+)/like', LikePost),
								('/([0-9]+)/new_comment', NewComment)
								],
								debug = True)