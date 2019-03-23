# -*- coding: utf-8 -*-
# @Author: longzx
# @Date: 2018-04-10 18:02:22

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, FileField, BooleanField, TextAreaField
from wtforms.validators import Required, Email, EqualTo
"""
字段类型      说　　明
StringField 文本字段
TextAreaField 多行文本字段
PasswordField 密码文本字段
HiddenField 隐藏文本字段
DateField 文本字段，值为 datetime.date 格式
DateTimeField 文本字段，值为 datetime.datetime 格式
IntegerField 文本字段，值为整数
DecimalField 文本字段，值为 decimal.Decimal
FloatField 文本字段，值为浮点数
BooleanField 复选框，值为 True 和 False
RadioField 一组单选框
SelectField 下拉列表
SelectMultipleField 下拉列表，可选择多个值
FileField 文件上传字段
SubmitField 表单提交按钮
FormField 把表单作为字段嵌入另一个表单
FieldList 一组指定类型的字段

验证函数 说　　明
Email 验证电子邮件地址
EqualTo 比较两个字段的值；常用于要求输入两次密码进行确认的情况
IPAddress 验证 IPv4 网络地址
Length 验证输入字符串的长度
NumberRange 验证输入的值在数字范围内
Optional 无输入值时跳过其他验证函数
Required 确保字段中有数据
Regexp 使用正则表达式验证输入值
URL 验证 URL
AnyOf 确保输入值在可选值列表中
NoneOf 确保输入值不在可选值列表中
"""


class NameForm(FlaskForm):
    username = StringField('用户名', validators=[Required()])
    password = PasswordField('密码', validators=[Required()])
    remember = BooleanField('记住我')
    submit = SubmitField('登录')

class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[Required()])
    password = PasswordField('密码', validators=[Required()])
    password2 = PasswordField('确认密码', validators=[Required(), EqualTo('password', message = '前后密码不一致')])
    email = StringField('邮箱', validators = [Required(), Email()])
    submit = SubmitField('注册')

class EditForm(FlaskForm):
    username = StringField('用户名')
    password = PasswordField('密码')
    password2 = PasswordField('确认密码', validators=[EqualTo('password', message = '前后密码不一致')])
    email = StringField('邮箱', validators = [Email()])
    introduction = StringField('签名')
    submit = SubmitField('修改')

class UploadForm(FlaskForm):
    artist = StringField('艺术家')
    introduction = TextAreaField('作品简介')
    file = FileField('文件地址')
    upload = SubmitField('上传作品')
