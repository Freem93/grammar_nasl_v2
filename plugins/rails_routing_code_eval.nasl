#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22204);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-4112");
  script_bugtraq_id(19454);
  script_osvdb_id(27822);

  script_name(english:"Ruby on Rails Routing Code URL Code Evaluation DoS");
  script_summary(english:"Tries to hang Ruby on Rails");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a code evaluation issue." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be using a version of Ruby on Rails,
an open source web framework, that has a flaw in its routing code that
can lead to the evaluation of Ruby code through the URL. Successful
exploitation of this issue can result in a denial of service or even
data loss." );
  # http://weblog.rubyonrails.org/2006/8/10/rails-1-1-6-backports-and-full-disclosure/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3d1f1cb" );
 script_set_attribute(attribute:"solution", value:
"Either apply the appropriate patch referenced in the vendor advisory
above or upgrade to Ruby on Rails 1.1.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/10");
 script_cvs_date("$Date: 2016/06/13 20:14:28 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/a:rubyonrails:ruby_on_rails");
 script_end_attributes();


  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:3000);


# Make sure it looks like Ruby on Rails.
r = http_send_recv3(method:"GET",item:"/rails_info/properties", port:port);
if (isnull(r)) exit(0);
res = r[2];
if ("only available to local requests." >!< res) exit(0);

if (safe_checks())
{
 # Try a request
 r = http_send_recv3(method:"GET",item:"/rails_generator", port:port);
 if (isnull(r)) exit(0);
 res = r[2];
 if ( ("<title>Action Controller: Exception caught</title>" >< res) &&
      ("Rails::Generator::GeneratorError" >< res) )
 {
  security_hole(port);
  exit (0);
 }

 # Try another one if rails_generator is not used
 r = http_send_recv3(method:"GET",item:"/fcgi_handler", port:port);
 if (isnull(r)) exit(0);
 res = r[2];
 if ( ("<title>Action Controller: Exception caught</title>" >< res) &&
      ("MissingSourceFile" >< res) && ("<pre>no such file to load -- fcgi</pre>" >< res))
 {
  security_hole(port);
  exit (0);
 }
}
else
{
 if (http_is_dead(port:port)) exit(0);

 # Try an exploit.
 r = http_send_recv3(method:"GET", item:"/breakpoint_client", port:port);
 # There's a problem if the server is now hung.
 if (http_is_dead(port:port)) security_hole(port);
}
