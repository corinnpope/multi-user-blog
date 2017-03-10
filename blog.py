import os
import re
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

# setup jinja
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
# fix "nameError: global name 'render_str' is not defined"
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# why wont my posts show up????
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

class Post(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	# TODO: add tags property?? 
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('/n', '<br>')
		return render_str("post.html", p = self)

	def get_post_id(self):
		return p.key().id()

class HomePage(BlogHandler):
	def get(self):
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
		self.render("home.html", posts = posts)

class PostPage(BlogHandler):
	def get(self, post_id):
		# convert post id to an int
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post)

class NewPost(BlogHandler):
	def get(self):
		self.render("new_post.html")

	def post(self):
		title = self.request.get('title')
		content = self.request.get('content')

		if title and content:
			# store to db if title and content are there
			p = Post(parent = blog_key(), title = title, content = content)
			p.put()
			self.redirect('/%s' % str(p.key().id()))

		else:
			error = "title and text are required"
			self.render("new_post.html", title = title, content = content, error = error)




app = webapp2.WSGIApplication([('/', HomePage),
								('/([0-9]+)', PostPage),
								('/new_post', NewPost),
								('/?', HomePage),
								],
								debug = True)