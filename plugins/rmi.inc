#TRUSTED a836b30a1d57c8aee2df2ed1bbe513ffbafd9e8303467e54ea5fff12fce122e5633d18da755e49c82fa465553274698661c53680f403afd419afaa1607f26df538106e5e22c715b524bb68f12f76ea558a67b38ba2623a9be5f656f183dd62980dd94c28aa184d0c155990f1c036ff90cefdd24d428092dcb70fb4cd789b195187617cad275e8769aea0c565ee18cc587a7ae27453e6666629ee0f3267fe3d97e05a1f5e38fa9a258e7402ce4465b9bcf15d4835dcc00f2da5c69d892a03845e1168ab7fa455fd85966c946b54cde5a958415e43bc13f009c31b0a71e68fe6c5d6f16e91b6f9e99621e34a86c4c3ecd13d2fee4ca0f9c4e26ab2c67b42497544cdc678b5e8943d2992242375a4f2b36053c92de3f63236e4201fa94b07a90216f7f68380839f56099f06a63254166a519995a76d124471b559def34f5a0840214cc09cfde9277e82e480700b5f1fa8b08c9bdb9848cdfbbf4119106de1129eb855bf9b1493086b486889632a3815c20b755dc39be3c87a18211dd85f59fc74b707f4426bac261e6f40efda982a184802ca7dcc816604aea4a3b45aa71d2edf504f5ccebaf11a12d598f97b1ffda86ae49b254c6481170832ae6dcbfcd7426d6b7a2d601e9b4fd985f046ea7558bd5a2e7391a7a02c40f104d6fbf02c39196183c41b760137ed305fad90d2142d9d497abdb22e5b4b76b2e0cad8456e1429070e
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision
#

##
# Establishes an RMI connection with the server. Upon
# success a new socket is returned. Audit is called if
# we are unable to connect or the protocol doesn't look
# right.
## 
function rmi_connect(port)
{
	local_var soc = open_sock_tcp(port);
	if (!soc) audit(AUDIT_NOT_LISTEN, "RMI", port);

	# Try to open an RMIv2 stream protocol (0x4b) connection.
	local_var request = 'JRMI\x00\x02\x4b'; 
	send(socket:soc, data:request);

	# Do a quick check to see if the response indicates RMI
	local_var res = recv(socket:soc, length:64, min:7);
	if (isnull(res) || strlen(res) < 7 ||
	  getbyte(blob:res, pos:0) != 0x4e ||
	  (getword(blob:res, pos:1) + 7) != strlen(res))
	{
	  close(soc);
	  audit(AUDIT_RESP_BAD, port);
	}

	return soc;
}
