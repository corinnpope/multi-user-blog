import utils

from google.appengine.ext import db


# ############Database: Users##########################
class User(db.Model):
	"""create a model for a site user with a name and pw"""
	name = db.StringProperty(required=True)
	password_hash = db.StringProperty(required=True)

	@classmethod
	def get_id(cls, uid):
		return User.get_by_id(uid, parent=utils.users_key())

	@classmethod
	def get_name(cls, name):
		# return User.all().filter('name =', name).get()
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw):
		password_hash = make_password_hash(name, pw)
		return User(
					parent=utils.users_key(),
					name=name,
					password_hash=password_hash)

	@classmethod
	def login(cls, name, pw):
		u = cls.get_name(name)
		if u and utils.valid_pw(name, pw, u.password_hash):
			return u


# #########Posts #########
# must go before comment class for referenceproperty() to work
class Post(db.Model):
	"""store posts in db with title, content, author, like count, user likes,
	created time, and last modified info"""
	title = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	author = db.StringProperty(required=True)
	like_count = db.IntegerProperty(default=0)
	user_like = db.StringListProperty()
	created = db.DateTimeProperty(auto_now_add=True)
	last_modified = db.DateTimeProperty(auto_now=True)

	def render(self):
		self._render_text = self.content.replace('/n', '<br>')
		return utils.render_str("post.html", p=self)


# Now add comments class
# referencing https://cloud.google.com/appengine/articles/modeling#one-to-many
class Comment(db.Model):
	"""store info about a post's comments via posted_to (referencing Post class),
	commentor (referencing User class), comment, and created"""
	posted_to = db.StringProperty(Post)
	commentor = db.StringProperty(User)
	comment = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	# ?? I thought this would be needed in permalink.html like 	{{post.render()
	# ...| safe}}...apparently NOT needed. Why?
	# def render(self):
	# 	self._render_text = self.comment.replace('/n', '<br>')
	# 	return render_str("comment.html", c = self)
# #################################################################