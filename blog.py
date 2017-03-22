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
import utils
from models import User, Post, Comment
from google.appengine.ext import db


class BlogHandler(webapp2.RequestHandler):
	"""handles basic methods for all blog pages"""
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = utils.jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	# Do Cookie Monster Stuff
	def set_cookie(self, name, val):
		cookie_value = utils.make_secure_val(val)
		# set and expiration time 2 weeks from now
		# expires = time.time() + 14 * 24 * 3600
		# strftime("%b %d, %Y", expires)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_value)
			)

	def read_cookie(self, name):
		cookie_value = self.request.cookies.get(name)
		return cookie_value and utils.check_secure_val(cookie_value)

	# ############login/logout/initialize ###################
	def login(self, user):
		self.set_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_cookie('user_id')
		self.user = uid and User.get_id(int(uid))

def login_required(BlogHandler):
    """
    A decorator to confirm a user is logged in or redirect as needed.
    """
    def login(self, *args, **kwargs):
        # Redirect to login if user not logged in, else execute func.
        if not self.user:
            self.redirect("/login")
        else:
            BlogHandler(self, *args, **kwargs)
    return login

# #Flailing here
class LikePost(BlogHandler):
    """Handler for Liking Posts"""
#  referenced https://discussions.udacity.com/t/stuck-on-getting-like-
# functionality-to-work/219359 && https://github.com/mangowolf/multi-user_blog
    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=utils.blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            if self.user.name != post.author:
            	# make sure user hasn't already like the post
                if self.user.name in post.user_like:
                    self.write("you can only like a post once")
                else:
                	# otherwise add the user to the list of those who liked it,
                	# increment likes, and redirect
                    post.user_like.append(self.user.name)
                    post.like_count = post.like_count + 1
                    post.put()
                    time.sleep(0.1)
                    self.redirect("/")
            if self.user.name == post.author:
            	# make sure user isnt the author
                self.write("you can't like your own post!")
        else:
            self.redirect("/login")


# TODO: Write unlike handler

# GAHHHHHHHHH
class HomePage(BlogHandler):
	def get(self):
		"""display the homepage with up to ten posts"""
		# for style...A MySQL literal string can contain a raw newline.
		# A Datastore GQL literal string cannot.
		# https://cloud.google.com/datastore/docs/reference/gql_reference
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")
		# comments = db.GqlQuery("SELECT * FROM Comment
		# ORDER BY created DESC limit 10")
		if self.user:
			self.render('home.html', posts=posts, username=self.user.name)
		else:
			self.render("home.html", posts=posts)


# ################################

class PostPage(BlogHandler):
	def get(self, post_id):
		"""method to display posts via permalink"""
		# convert post id to an int
		key = db.Key.from_path('Post', int(post_id), parent=utils.blog_key())
		post = db.get(key)
		# check to see if post exists, if it does get into
		if post is not None:
			post_id_num = post.key().id()
			# find all the comments for the current post
			comments = Comment.all().filter('posted_to =', str(post_id_num))
			# get the username if they're logged in, otherwise set it to none
			if self.user:
				username = self.user.name
			else:
				username = None
			
			# get the permalink page
			self.render(
				"permalink.html",
				post=post,
				comments=comments,
				username = username
				)
		# if the page doesn't exist, redirect home
		else:
			self.redirect('/')


class NewPost(BlogHandler):
	@login_required
	def get(self):
		if self.user:
			self.render("new_post.html", username = self.user.name)
		else:
			self.render("login.html")

	@login_required
	def post(self):
		title = self.request.get('title')
		content = self.request.get('content')
		author = self.user.name
		# create an empty array for users who have liked the post
		user_like = []

		if title and content:
			# store to db if title and content are there
			p = Post(
				parent=utils.blog_key(),
				title=title,
				content=content,
				author=author)
			p.put()
			# otherwise updating lags
			time.sleep(0.1)
			self.redirect('/%s' % str(p.key().id()))

		else:
			error = "title and text are required"
			self.render(
				"new_post.html",
				title=title,
				content=content,
				author=author,
				error=error)


class EditPost(BlogHandler):
	@login_required
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=utils.blog_key())
		post = db.get(key)
		# check to see if post exists
		if post is not None:
			if self.user.name == post.author:
				self.render('edit_post.html', post=post)
			else:
				error = "you cannot edit another user's posts. please log in as \
						 the author. "
				self.render('error.html', error=error)
				# redirecting to login from error page

	@login_required
	def post(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=utils.blog_key())
		post = db.get(key)
		# check to see if post exists
		if post is not None:
			# check that the current user is the author
			if self.user.name == post.author:
				# get what is changed
				post.title = self.request.get('title')
				post.content = self.request.get('content')
				# and put it in the db
				post.put()
				# include this, otherwise updating lags
				time.sleep(0.1)
				self.redirect('/')
			else:
				self.redirect('/login')
		else:
			self.redirect('/')


class DeletePost(BlogHandler):
	@login_required
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=utils.blog_key())
		post = db.get(key)
		if post is not None:
			# users can only delete their own posts
			if self.user.name == post.author:
				self.render('delete_post.html', post=post)
			else:
				error = "you cannot delete another user's posts. please log in \
						as the author. "
				self.render('error.html', error=error)

	@login_required
	def post(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=utils.blog_key())
		post = db.get(key)
		# check to see if post exists
		if post is not None:
			if self.user.name == post.author:
				key = db.Key.from_path('Post', int(post_id), parent=utils.blog_key())
				post = db.get(key)
				post.delete()
				# otherwise updating lags
				time.sleep(0.1)
				self.redirect('/')
			else:
				self.redirect('login')
		else:
			self.redirect('/')


# ########### Now for Comments ########################
class NewComment(BlogHandler):
	@login_required
	def get(self, post_id):
		post = Post.get_by_id(int(post_id), parent=utils.blog_key())
		# similar to how posts are liked
		if post is None:
			# this makes sure that the post exists
			self.redirect('/')
		else:
			username = self.user.name
			self.render("new_comment.html", post_id=post_id, username = username)

	@login_required
	def post(self, post_id):
		post_key = db.Key.from_path('Post', int(post_id), parent=utils.blog_key())
		post = db.get(post_key)

		# get the comment text and the current post
		comment = self.request.get('comment')
		posted_to = str(post.key().id())

		# check to see if post exists
		if not post:
			# if post does not exist
			return self.error(404)

		if comment:
			# store to db if title and content are there
			commentor = self.user.name
			print(commentor)
			c = Comment(
				parent=utils.blog_key(),
				comment=comment,
				posted_to=posted_to,
				commentor=commentor)
			c.put()
			# Just some debugging to make sure things are being saved to db
			# print("comment:" + c.comment)
			# print("posted to:" + c.posted_to)
			# print("commentor" + c.commentor)
			# print('/%s' % str(post.key().id()))
			# otherwise updating lags
			time.sleep(0.1)
			self.redirect('/%s' % str(post.key().id()))
		else:
			error = "you must enter text"
			# TODO change to edit_comment
			self.render('%s' % str(post.key().id()), post=post, error=error)


class EditComment(BlogHandler):
	@login_required
	def get(self, post_id):
		key = db.Key.from_path('Comment', int(post_id), parent=utils.blog_key())
		comment = db.get(key)
		# check to make sure comment exists
		if comment is not None:
			# make sure current user is the comment owner
			if self.user.name == comment.commentor:
				username = self.user.name
				self.render('edit_comment.html', comment=comment, username = username)
			else:
				error = "you cannot edit another user's comments. please log in \
						as the author. "
				self.render('error.html', error=error)
				# redirecting to login from error page
		else:
			self.redirect('/')

	@login_required
	def post(self, post_id):
		key = db.Key.from_path('Comment', int(post_id), parent=utils.blog_key())
		comment = db.get(key)
		# again, check to make sure comment exists
		if comment is not None:
			# check to make sure current user is comment owner
			if self.user.name == comment.commentor:
				# get the comment from the page if updated
				comment.comment = self.request.get('comment')
				comment.put()
				# otherwise updating lags
				time.sleep(0.1)
				self.redirect('/')
			else:
				self.redirect('/')
		else:
			self.redirect('/')


class DeleteComment(BlogHandler):
	@login_required
	def get(self, post_id):
		key = db.Key.from_path('Comment', int(post_id), parent=utils.blog_key())
		comment = db.get(key)
		if comment is not None:
			# make sure comment owner is current user
			if self.user.name == comment.commentor:
				username = self.user.name
				self.render('delete_comment.html', comment=comment, username = username)
			else:
				error = "you cannot delete another user's comments. please log in \
				as the author. "
				self.render('error.html', error=error)
		else:
			self.redirect('/')

	@login_required
	def post(self, post_id):
		key = db.Key.from_path('Comment', int(post_id), parent=utils.blog_key())
		comment = db.get(key)
		# check to see comment exists
		if comment is not None:
			# make sure comment owner is current user
			if self.user.name == comment.commentor:
				comment.delete()
				# otherwise updating lags
				time.sleep(0.1)
				self.redirect('/')
			else:
				self.redirect('login')
		else:
			self.redirect('/')


# ######### User Signup and Confirmation/Save ###########
def valid_username(username):
	"""Check for valid username """
	USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	return username and USER_RE.match(username)


def valid_password(password):
	"""regex to check password validity"""
	PASS_RE = re.compile(r"^.{3,20}$")
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

		params = dict(username=self.username)

		# validation
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
		"""check to see if user exists and log them in if true"""
		u = User.get_name(self.username)
		if u:
			msg = "Username taken"
			self.render('signup.html', error_username=msg)
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
			self.render('login.html', error=msg)


class LogOut(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/')


app = webapp2.WSGIApplication([
								('/', HomePage),
								('/([0-9]+)', PostPage),
								('/new_post', NewPost),
								('/?', HomePage),
								('/login', LogIn),
								('/logout', LogOut),
								('/signup', SaveUser),
								('/edit_post/(\d+)', EditPost),
								('/delete_post/(\d+)', DeletePost),
								('/([0-9]+)/like', LikePost),
								('/([0-9]+)/new_comment', NewComment),
								('/([0-9]+)/edit_comment', EditComment),
								('/([0-9]+)/delete_comment', DeleteComment)
								], debug=True)
