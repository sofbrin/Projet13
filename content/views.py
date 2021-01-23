from django.shortcuts import render


def index(request):
    """ Rendering home page """
    page_title = {"page_title": "Accueil"}
    return render(request, 'content/index.html', page_title)
