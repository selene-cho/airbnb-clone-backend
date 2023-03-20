import jwt
import requests
from django.contrib.auth import authenticate, login, logout
from django.conf import settings
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.exceptions import ParseError, NotFound
from rest_framework.permissions import IsAuthenticated
from .serializers import PrivateUserSerializer
from users.models import User


class Me(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = PrivateUserSerializer(user).data
        return Response(serializer)

    def put(self, request):
        user = request.user
        serializer = PrivateUserSerializer(
            user,
            data=request.data,
            partial=True,
        )
        if serializer.is_valid():
            user = serializer.save()
            serializer = PrivateUserSerializer(user)
            return Response(serializer.data)
        else:
            return Response(serializer.errors)


class Users(APIView):
    def post(self, request):
        password = request.data.get("password")
        if not password:
            raise ParseError
        serializer = PrivateUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(password)
            user.save()
            serializer = PrivateUserSerializer(user)
            return Response(serializer.data)
        else:
            return Response(serializer.errors)


class PublicUser(APIView):
    def get(self, request, username):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise NotFound
        serializer = PrivateUserSerializer(user)
        return Response(serializer.data)


class ChangePassword(APIView):

    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        if not old_password or not new_password:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        if user.check_password(old_password):  # 이전 비밀번호와 동일한지 check
            user.set_password(new_password)
            user.save()
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class LogIn(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if not username or not password:
            raise ParseError
        user = authenticate(
            request,
            username=username,
            password=password,
        )  # username과 password가 일치하는지 check
        if user:
            login(request, user)  # 로그인 하고 동시에 세션과 쿠키 발급
            return Response({"ok": "Welcome"})
        else:
            return Response({"error": "wrong password"})


class LogOut(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({"ok": "bye"})


class JWTLogIn(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if not username or not password:
            raise ParseError
        user = authenticate(
            request,
            username=username,
            password=password,
        )
        if user:
            token = jwt.encode(
                {"pk": user.pk},
                settings.SECRET_KEY,
                algorithm="HS256",
            )
            return Response({"token": token})
        else:
            return Response({"error": "wrong password"})

class GithubLogIn(APIView):
    def post(self, request):
        try:
            code = request.data.get("code")  # 프론트에서 보내준 code 받음
            access_token = requests.post(   # github API로 code를 access token으로 바꿔줌
                f"https://github.com/login/oauth/access_token?code={code}&client_id=edcf66f77540403846ca&client_secret={settings.GH_SECRET}",   # user가 준 code, github에 등록한 client_id, github 페이지에 있는 client secret도 같이 보내야함
                headers={"Accept": "application/json"},
            )
            access_token = access_token.json().get("access_token")   # github으로 요청 보내면 access_token을 받음
            user_data = requests.get(   # 우리가 user인 것처럼 github API에게 user에 대한 정보 받을 수 있음
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )  # user_data 받음
            user_data = user_data.json()
            user_emails = requests.get(   # email은 암호화 되어 있기 때문에 요청 또 보내야함
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            user_emails = user_emails.json()
            try:  # 이메일을 가진 user를 database에서 찾으면 user는 github을 통해 로그인 한다는 뜻
                user = User.objects.get(email=user_emails[0]["email"])
                login(request, user)  # 같은 email이 있다면 로그인 시켜주면 됨
                return Response(status=status.HTTP_200_OK)
            except User.DoesNotExist:  # 같은 email을 가진 user가 없다면
                user = User.objects.create(  # 새로운 User 생성 , 정보 아래에서 가져옴
                    username=user_data.get("login"),
                    email=user_emails[0]["email"],
                    name=user_data.get("name"),
                    avatar=user_data.get("avatar_url"),
                )
                user.set_unusable_password()  # 이 user는 비밀번호 없는 user -> 그냥 로그인 하려고 하면 비밀번호 없다고 sns 로그인해! 알려줌
                user.save()  # user 저장
                login(request, user)  # 그후 로그인시켜줌 login 함수 호출할때 이 함수가 모든 걸 다 처리해 줌
                # 백엔드에서 세션 만들어줌, user한테 cookie 줌 ... 다 해줌
                return Response(status=status.HTTP_200_OK) # status success 해주고 프론트엔드로 GO!
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)
