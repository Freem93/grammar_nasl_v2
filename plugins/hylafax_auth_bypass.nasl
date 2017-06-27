#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20387);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-3538");
  script_bugtraq_id(16150);
  script_osvdb_id(22245);
 
  script_name(english:"HylaFAX hfaxd with PAM Password Policy Bypass");
  script_summary(english:"Checks for password check vulnerability in HylaFAX hfaxd");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote fax server fails to properly validate passwords." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HylaFAX, a fax / pager server application
for Linux / unix. 

The version of HylaFAX installed on the remote host does not check
passwords when authenticating users via hfaxd, its fax server.  An
attacker can exploit this issue to bypass authentication using a valid
username and gain access to the system." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.hylafax.org/bugzilla/show_bug.cgi?id=682" );
 script_set_attribute(attribute:"see_also", value:"http://www.hylafax.org/content/HylaFAX_4.2.4_release" );
 script_set_attribute(attribute:"solution", value:
"Rebuild HylaFAX with PAM support or upgrade to HylaFAX version 4.2.4
or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/04");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/hylafax", 4559);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_kb_item("Services/hylafax");
if (!port) port = 4559;
if (!get_port_state(port)) exit(0);


# Try to exploit the flaw.
soc = open_sock_tcp(port);
if (soc) {
  foreach user (make_list("fax", "guest", "root")) {
    # There's a problem if we can log in using a random password.
    pass = rand_str();
    if (ftp_authenticate(socket:soc, user:user, pass:pass)) {
        report = string(
          "Nessus was able to log in using the following credentials :\n",
          "\n",
          "  User:     ", user, "\n",
          "  Password: ", pass, "\n"
        );

      security_hole(port:port, extra:report);
      exit(0);
    }
  }

  ftp_close(socket:soc);
}
