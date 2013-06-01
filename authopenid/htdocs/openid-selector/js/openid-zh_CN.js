/*
	Simple OpenID Plugin
	http://code.google.com/p/openid-selector/
	
	This code is licensed under the New BSD License.
*/

var providers_large = {
	google : {
		name : 'Google',
		url : 'https://www.google.com/accounts/o8/id'
	},
	yahoo : {
		name : 'Yahoo',
		url : 'http://me.yahoo.com/'
	},
	aol : {
		name : 'AOL',
		label : '请输入你的 AOL 用户名。',
		url : 'http://openid.aol.com/{username}'
	},
	myopenid : {
		name : 'MyOpenID',
		label : '请输入你的 MyOpenID 用户名。',
		url : 'http://{username}.myopenid.com/'
	},
	openid : {
		name : 'OpenID',
		label : '请输入你的 OpenID。',
		url : null
	}
};

var providers_small = {
	livejournal : {
		name : 'LiveJournal',
		label : '请输入你的 Livejournal 用户名。',
		url : 'http://{username}.livejournal.com/'
	},
	/* flickr: {
		name: 'Flickr',        
		label: '请输入你的 Flickr 用户名。',
		url: 'http://flickr.com/{username}/'
	}, */
	/* technorati: {
		name: 'Technorati',
		label: '请输入你的 Technorati 用户名。',
		url: 'http://technorati.com/people/technorati/{username}/'
	}, */
	wordpress : {
		name : 'Wordpress',
		label : '请输入你的 Wordpress.com 用户名。',
		url : 'http://{username}.wordpress.com/'
	},
	blogger : {
		name : 'Blogger',
		label : '你的 Blogger 帐号',
		url : 'http://{username}.blogspot.com/'
	},
	verisign : {
		name : 'Verisign',
		label : '你的 Verisign 用户名',
		url : 'http://{username}.pip.verisignlabs.com/'
	},
	/* vidoop: {
		name: 'Vidoop',
		label: '你的 Vidoop 用户名',
		url: 'http://{username}.myvidoop.com/'
	}, */
	/* launchpad: {
		name: 'Launchpad',
		label: '你的 Launchpad 用户名',
		url: 'https://launchpad.net/~{username}'
	}, */
	claimid : {
		name : 'ClaimID',
		label : '你的 ClaimID 用户名',
		url : 'http://claimid.com/{username}'
	},
	clickpass : {
		name : 'ClickPass',
		label : '输入你的 ClickPass 用户名',
		url : 'http://clickpass.com/public/{username}'
	},
	google_profile : {
		name : 'Google Profile',
		label : '输入你的 Google Profile 用户名',
		url : 'http://www.google.com/profiles/{username}'
	}
};

openid.locale = 'zh_CN';
openid.sprite = 'en'; // reused in german& japan localization
openid.demo_text = '在客户演示模式下。 通常会提交 OpenID：';
openid.signin_text = '登录';
openid.image_title = '使用 {provider} 登录';
