from django.urls import path
from .views import index
#from .views import HomeView, ArticleDetailView, AddPostView, UpdatePostView, DeletePostView, AddCategoryView, \
    #CategoryView, CategoryListView, LikeView, AddCommentView

urlpatterns = [
   path('', index, name='home'),
]
