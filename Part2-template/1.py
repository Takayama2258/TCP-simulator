# n = int(input("please input a factor"))
# f = int(input())

# def fi(i):
#     if i % f ==0:
#         return False
#     return True

# l = list(range(1,n+1))
# while f!=-1:
#     l = list(filter(fi,l))
#     print(len(list(l)))
#     f = int(input())

prices = []

def input_price(prices):
    temp = input()
    while temp!="":
        i=0
        item=""
        while(temp[i]!=" "):
            item+=temp[i]
            i+=1
        price = temp[i+1:]
        price = int(price)
        prices.append((item,price))
        temp = input()
    return prices
def print_menu(prices):
    print("========menu========")
    for i in range(len(prices)):
        print(i+1,end="")
        print(". "+prices[i][0]+" $"+str(prices[i][1]))
def take_order(prices):
    print("please input...")
    temp=input()
    cost = 0
    while temp!="":
        item, number = temp.split(" ")
        item = int(item)
        number=int(number)
        cost+=prices[item-1][1]*number
        temp = input()
    print(cost)

print("...")
choice=input("please input an option no.: ")
while True:
    if choice =='4':
        break
    elif choice=='1':
        prices=input_price(prices)
    elif choice=='2':
        print_menu(prices)
    elif choice=='3':
        take_order(prices)
    choice=input("Please input an option no.: ")