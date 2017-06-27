#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33948);
  script_version("$Revision: 1.15 $");

  script_cve_id(
    "CVE-2006-2937",
    "CVE-2006-2940",
    "CVE-2007-3108",
    "CVE-2008-1483",
    "CVE-2008-1657",
    "CVE-2008-6021"
  );
  script_bugtraq_id(28444, 30723);
  script_osvdb_id(29260, 29261, 37055, 43745, 43911, 48607);
  script_xref(name:"Secunia", value:"31531");

  script_name(english:"Attachmate Reflection for Secure IT UNIX server < 7.0 SP1 Multiple Vulnerabilities");
  script_summary(english:"Checks if SSH banner < 7.0.1.575");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Attachmate Reflection for Secure IT UNIX server
installed on the remote host is less than 7.0 SP1 and thus reportedly
affected by several issues :

  - There is an inherited vulnerability in OpenSSL when
    parsing malformed ASN.1 structures leading to a
    denial of service vulnerability (CVE-2006-2937).

  - There is an inherited vulnerability in OpenSSL when
    parsing parasitic public keys leading to a
    denial of service vulnerability (CVE-2006-2940).

  - There is an inherited vulnerability in OpenSSL when
    performing Montgomery multiplication, leading to a
    side-channel attack vulnerability (CVE-2007-3108).

  - There is an inherited vulnerability in OpenSSH with the
    execution of the ~/.ssh2/rc session file
    (CVE-2008-1657).

  - There is an issue with the security of forwarded X11
    connections, leading to possible hijacking.
    (CVE-2008-1483)

  - There are multiple unspecified other vulnerabilities.
    (CVE-2008-6021)" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e28db404" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Attachmate Reflection for Secure IT UNIX server 7.0 SP1." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/28");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");

# Don't flag Windows hosts
os = get_kb_item("Host/OS");
if (os && "Windows" >< os) audit(AUDIT_OS_NOT, "a Unix and Unix-like OS", "Microsoft Windows");

port = get_kb_item("Services/ssh");
if (!port) port = 22;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Check the version in the banner.
banner = get_kb_item("SSH/banner/" + port);
if (!banner) audit(AUDIT_WEB_BANNER_NOT, port);
if ("ReflectionForSecureIT_" >!< banner) audit(AUDIT_NOT_LISTEN, "Attachmate Reflection for Secure IT UNIX server", port);

ver = strstr(banner, "ReflectionForSecureIT_") - "ReflectionForSecureIT_";
if (!ver) audit(AUDIT_SERVICE_VER_FAIL, "Attachmate Reflection for Secure IT UNIX server SSH", port);

arr = split(ver, sep:".", keep:FALSE);

for ( i = 0 ; i < max_index(arr) ; i ++ )
{
 arr[i] = int(arr[i]);
}

vuln = FALSE;

if (arr[0] && arr[0] < 7) vuln = TRUE;
if (arr[0] && arr[0] == 7 && arr[1] && arr[1] == 0)
{
  if (arr[2] && arr[2] < 1) vuln = TRUE;
  if (arr[2] && arr[2] == 1 && arr[3] && arr[3] < 575) vuln = TRUE;
}

if (vuln)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote Attachmate Reflection for Secure IT UNIX server returned\n",
      "the following banner :\n",
      "\n",
      "  ", banner, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Attachmate Reflection for Secure IT UNIX server", port, ver);
