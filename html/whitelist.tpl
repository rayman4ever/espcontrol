<html><head>
<title>ESPLight Server - White list</title>
<link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
<br/>
<div align="center" id="%STATUS_STYLE%">%STATUS_MSG%</div>
<br/>
<div id="main">
<h1>White list</h1>
<h3>Current Status :</h3>
<p>Security Mode <font color="%STATUS_COLOR%">%SECURITY_STATUS%</font> <a href="whitelist/update.cgi?set=%SECURITY_SET%">Change</a></p>
<h3>Your Information :</h3>
<p>IP: %IP%</p>
<p>MAC Address : %MAC%</p>
<h3>Current allowed devices :</h3>
<form method="post" action="whitelist/del.cgi" >
<div>
<table>
	<tr>
		<td>Index</td>
		<td>MAC Address</td>
		<td>Delete</td>
	</tr>
	%repeater%
</table>
</div>
</form>
<h3>Add new device</h3>
<h4>Please note the device supports up to %maxdevices% devices only</h4>
<form method="post" action="whitelist/add.cgi">
<div>
MAC Address :
<input type="text" name="macaddr"/>
<input type="submit" value="Add"/>
</div>
</form>
<div align="center"><a href="whitelist/update.cgi?update=1">Save</a></div>
</div>
</body></html>

