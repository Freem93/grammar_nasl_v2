#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33589);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_name(english:"Openlink Virtuoso Server Default Credentials");
  script_summary(english:"Logs in with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote service is protected with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Openlink Virtuoso server is configured to use default
credentials to control access.");
  script_set_attribute(attribute:"solution", value:"Change the password immediately.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"Databases");

  script_dependencies("openlink_virtuoso_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports(1111,"Services/openlink-virtuoso");
  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('byte_func.inc');


port = get_service(svc:"openlink-virtuoso", default:1111, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# Make a list of default users to log in.
# According to the documentation default users are "dav","vad","demo",
# "soap","fori" and "dba". However, only user dba is active.

users = make_list("dba","dav","vad","demo","soap","fori");

id    = 1 ; # Connection identifier
info = NULL;

foreach user (users)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    # Send a identification request.
    req =
      mkword(0xbcc1) +
      mkword(0xbc05) +
      mkword(0xbc01) +
      mkword(0xbc00) +
      mkbyte(0)      +	 # May be end of msg
      mkword(0x15b5) +  # 0xb5 = msg code for size 0x15 == size
      "caller_identification" +
      mkword(0xbcc1) +
      mkword(0xbc01) +
      mkbyte(0) ;	 # May be end of msg

    send(socket:soc, data:req);
    res = recv(socket:soc, min:43, length:1024);

    if (res)
    {
      # Check if we get port number in response.
      if (strlen(res) >= 43 && port == substr(res,15,18))
      {
        # Send SCON command with default user/passwd combination
        length = strlen(user);

        req2 =
          mkword(0xbcc1)    +
          mkword(0xbc05)    +
          mkword(0xbc01)    +
          mkbyte(id)        + # id == Connection identifier
          mkbyte(0xbc)      +
          mkbyte(0)         + # May be end of msg
          mkword(0x04b5)    + # 0xb5 = msg size code, size 0x04 == size
          "SCON"	          +
          mkword(0xbcc1)    +
          mkbyte(0x04)      + # ?
          mkbyte(0xb5)      + # 0xb5 = msg size code
          mkbyte(length)    + # length
          user 	          +
          mkbyte(0xb5)      + # 0xb5 = msg code for size
          mkbyte(length)    + # 0xb5 = msg code for size
          user 	          +
          mkword(0x0ab5)    + # Send Version
          "05.00.3028"      +
          mkword(0xbcc1)    +
          mkbyte(0x06)      + # ?
          mkword(0x06b5)    + # Send Client Name
          "NESSUS"          +
          mkword(0x00bd)    +
          mkword(0x0c00)    +
          mkbyte(0xb4)      +
          mkword(0x0fb5)    + # Send Hostname
          "OpenLinkVituoso" +
          mkword(0x05b5)    + # 0xb5 = msg code for size
          "Win32"           +
          mkword(0x00b5)    + # 0xb5 = msg code for size
          mkword(0x00bc) ;
        send(socket:soc, data:req2);
        res = recv(socket:soc, length:1024);

        # If we could login successfully ...
        if (
          strlen(res) &&
          "SQL_TXN_ISOLATION"    >< res &&
          "SQL_BINARY_TIMESTAMP" >< res
        )
        {
          # Send a close request, or else the connection limitation is
	  # is exceeded.
          cls =
            mkdword(0xbc05bcc1) +
            mkdword(0xbc06bc01) +
            mkbyte(0x00) +
            mkword(0x04b5) +
            "FRST" + mkbyte(0xc1) +
            mkdword(0x0cb502bc) +
            mkbyte(0x73) 	    +
            port +
            mkdword (0x2d5f365f) +
            mkword (0x5f31) +
            mkbyte (0x30) +
            mkword(0x00bc)	;

          # Send FRST twice.
          send(socket:soc, data:cls);
          res3 = recv(socket:soc, min:34, length:1024);
          send(socket:soc, data:cls);
          res3 = recv(socket:soc, min:34, length:1024);

          info += " " + user + " : " + user + '\n';
        }
      }

      id += 3;
    }
    close(soc);
  }
}

if (info)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus logged in with the following credentials : \n' +
      '\n' +
      info;
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, "affected");
