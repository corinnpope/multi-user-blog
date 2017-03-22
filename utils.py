import random
import hmac
import string
import hashlib
from google.appengine.ext import db
import os
import jinja2


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


secret = 'udacity_full_stack'


# fix "nameError: global name 'render_str' is not defined"
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)


def render_post(response, post):
	# bold and break the post title
	response.out.write('<b>' + post.title + '</b><br>')
	response.out.write(post.content)


def render_comment(response, comment):
	response.out.write(comment.comment)


def make_secure_val(val):
	# make sure user & cookie values match
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
	"""split the secure val at the pipe and make sure they're the same"""
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val


# make things secure
def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))


def make_password_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)


#  make sure pw hash is same as hash
def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_password_hash(name, password, salt)


# users and blog key
def users_key(group='default'):
	return db.Key.from_path('users', group)


def blog_key(name='default'):
	return db.Key.from_path('blogs', name)


# TODO add comments_key
# should this be group or name??
def comments_key(group='defaut'):
	return db.Key.from_path('comments', name)