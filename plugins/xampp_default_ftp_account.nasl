#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18037);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2017/03/07 17:25:25 $");

 script_cve_id("CVE-2005-1078");
 script_bugtraq_id(13131);
 script_osvdb_id(15636);

 script_name(english:"XAMPP Default FTP Account");
 script_summary(english:"Attempts to log in via FTP using credentials associated with XAMPP.");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has an account that is protected with default
credentials." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server has an account with a known username / password
combination that might have been configured when installing XAMPP. An
attacker may be able to use this to gain authenticated access to the
system, which could allow for other attacks against the affected
application and host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Apr/256");
 script_set_attribute(attribute:"solution", value:
"Modify the FTP password of the remote host." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:W/RC:X");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:xampp:apache_distribution");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

 script_dependencie("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("global_settings/supplied_logins_only");

 exit(0);
}

#
# The script code starts here
#
include('audit.inc');
include('global_settings.inc');
include('ftp_func.inc');

port = get_ftp_port(default:21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (get_kb_item('ftp/'+port+'/AnyUser'))
  audit(AUDIT_FTP_RANDOM_USER, port);

i = 0;
users[i] = "nobody";
passes[i] = "xampp";

i++;
users[i] = "nobody";
passes[i] = "lampp";

# nb: this is the default in 1.4.13.
i++;
users[i] = "newuser";
passes[i] = "wampp";

info = "";
for (j=0; j<=i; j++)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  user = users[j];
  pass = passes[j];
  if (ftp_authenticate(socket:soc, user:user, pass:pass))
  {
    info += '  - ' + user + '/' + pass + '\n';
    if (!thorough_tests) break;
  }
  close(soc);
 }
}


if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report =
      '\n' +
      'Nessus uncovered the following set'+ s + ' of default credentials :\n' +
      info + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
