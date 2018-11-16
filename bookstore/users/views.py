from django.shortcuts import render,redirect,reverse
from .models import Passport,Address
import re
from django.http import JsonResponse
from utils.decorators import login_required

# Create your views here.

def register(request):
    '''显示用户注册页面'''
    return render(request, 'users/register.html')

def register_handle(request):
    '''进行用户注册处理'''
    
    username = request.POST.get('user_name')
    password = request.POST.get('pwd')
    email = request.POST.get('email')

    
    if not all([username, password, email]):
        
        return render(request, 'users/register.html', {'errmsg': '参数不能为空!'})

    
    if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
        
        return render(request, 'users/register.html', {'errmsg': '邮箱不合法!'})

    
    # 进行业务处理:注册，向账户系统中添加账户
    # Passport.objects.create(username=username, password=password, email=email)
    try:
        Passport.objects.add_one_passport(username=username, password=password, email=email)
    except Exception as e:
        print("e:", e)
        return render(request, 'users/register.html', {'errmsg': '用户名已存在！'})

    
    return redirect(reverse('books:index'))


def login(request):
    if request.COOKIES.get("username"):
        username = request.COOKIES.get("username")
        checked = 'checked'
    else:
        username = ''
        checked = ''

    context = {
        'username':username,
        'checked ':checked,
}

    return render(request,'users/login.html', context)


def login_check(request):
    '''进行用户登录校验'''
    # 1.获取数据
    username = request.POST.get('username')
    password = request.POST.get('password')
    remember = request.POST.get('remember')

    # 2.数据校验
    if not all([username, password, remember]):
        # 有数据为空
        return JsonResponse({'res': 2})

    # 3.进行处理:根据用户名和密码查找账户信息
    passport = Passport.objects.get_one_passport(username=username, password=password)

    if passport:
        next_url = reverse('books:index') # /user/
        jres = JsonResponse({'res': 1, 'next_url': next_url})

        # 判断是否需要记住用户名
        if remember == 'true':
            # 记住用户名
            jres.set_cookie('username', username, max_age=7*24*3600)
        else:
            # 不要记住用户名
            jres.delete_cookie('username')

        # 记住用户的登录状态
        request.session['islogin'] = True
        request.session['username'] = username
        request.session['passport_id'] = passport.id
        return jres
    else:
        # 用户名或密码错误
        return JsonResponse({'res': 0})


def logout(request):
    #清空session信息
    request.session.flush()
    return redirect(reverse('books:index'))

@login_required
def user(request):
    '''用户中心'''
    passport_id = request.session.get('passport_id')
    addr = Address.objects.get_default_address(passport_id=passport_id)
    books_li = []
    context = {
        'addr':addr,
        'page':user,
        'books_li':books_li
}
    return render(request, 'users/user_center_info.html', context)
