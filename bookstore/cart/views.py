from django.shortcuts import render
from books.models import Books
from django.http import JsonResponse
from django_redis import get_redis_connection
from utils.decorators import login_required

# Create your views here.
@login_required
def cart_add(request):
    #前端传来post数据
    books_id = request.POST.get('books_id')
    books_count = request.POST.get('books_count')
    #判断是否合法
    if not all([books_id, books_count]):
        return JsonResponse({'res':1, 'errmsg':'数据不完整'})
    books = Books.objects.get_books_by_id(books_id=books_id)
    if books is None:
        return JsonResponse({'res':2, 'errmsg':'商品不存在'})
    try:
        count = int(books_count)
    except Exception as e:
        print("e: ", e)
        return JsonResponse({'res':3, 'errmsg':'商品数量必须为数字'})

    #接受后添加到购物车
    #购物记录用hash保存，cart_用户id: 商品id 商品数量
    conn = get_redis_connection('default')
    cart_key = 'cart_%d' % request.session.get('passport_id')
    res = conn.hget(cart_key, books_id)
    if res is None:
        res = count
    else:
        res = int(res) + count
    if res > books.stock:
        return JsonResponse({'res': 4,'errmsg':'商品库存不足'})
    else:
        conn.hset(cart_key, books_id, res)
    return JsonResponse({'res': 5})

@login_required
def cart_count(request):
    '''获取用户购物车中的商品树木'''
    conn = get_redis_connection('default')
    cart_key = 'cart_%d' % request.session.get('passport_id')
    #res = conn.hlen(cart_key)
    res = 0
    res_list = conn.hvals(cart_key)
    for i in res_list:
        res += int(i)
    return JsonResponse({'res': res})

@login_required
def cart_show(request):
    '''显示用户购物车的记录'''
    passport_id = request.session.get('passport_id')
    conn = get_redis_connection('default')
    cart_key = 'cart_%d' % passport_id
    res_dict = conn.hgetall(cart_key)

    books_li = []
    #保存所有商品总数
    total_count = 0
    #保存所有商品的总价
    total_price = 0

    for id, count in res_dict.items():
        books = Books.objects.get_books_by_id(books_id=id)
        books.count = count
        books.anount = int(count) * books.price
        # books_li.append((books, count))
        books_li.append(books)
        
        total_count += int(count)
        total_price += int(count) * books.price
    
    context = {
        'books_li': books_li,
        'total_count': total_count,
        'total_price': total_price,
    }
    
    return render(request, 'cart/cart.html', context)


@login_required
def cart_del(request):
    books_id = request.POST.get('books_id')
    if not all([books_id]):
        return JsonResponse({'res':1, 'errmsg':'数据不完整'})
    books = Books.objects.get_books_by_id(books_id=books_id)
    if books is None:
        return JsonResponse({'res': 2,'errmsg': '商品不存在'})

    conn = get_redis_connection('default')
    cart_key = 'cart_%d' % request.session.get('passport_id')
    conn.hdel(cart_key, books_id)

    return JsonResponse({'res': 3})

@login_required
def cart_update(request):
    books_id = request.POST.get('books_id', '')
    books_count = request.POST.get('books_count', '')

    if not all([books_id, books_count]):
        return JsonResponse({'res': 1, 'errmsg': '数据不完整'})
    books = Book.objects.get_books_by_id(books_id=books_id)
    if books is None:
        return JsonResponse({'res':2,'errmsg':'商品不存在'})

    try:
        books_count = int(books_count)
    except Exception as e:
     print("e: ", e)
    return JsonResponse({'res': 3,'errmsg': '商品数目必须为数字'})

    conn = get_redis_connection('default')
    cart_key = 'cart_%d' % request.session.get('passport_id')

    if books_count > books.stock:
        return JsonResponse({'res': 4,'errmsg': '商品库存不足'})
    conn.hset(cart_key, books_id, books_count)

    return JsonResponse({'res': 5})
