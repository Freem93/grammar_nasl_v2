#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20932);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-0711");
  script_bugtraq_id(16651);
  script_osvdb_id(23158);

  script_name(english:"NeoMail Session ID Weakness neomail-prefs.pl Arbitrary Mail-folder Manipulation");
  script_summary(english:"Checks for session id validation vulnerability in NeoMail");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl application that is affected by
an access validation failure." );
 script_set_attribute(attribute:"description", value:
"The remote host is running NeoMail, an open source webmail application
written in Perl. 

The installed version of this software fails to validate the
'sessionid' parameter in the 'neomail-prefs.pl' script as a valid
session identifier.  An unauthenticated attacker may be able to
exploit this issue to create or delete arbitrary mail-folder files on
the affected host subject to the permissions of the group id under
which the affected application operates. 

Note that successful exploitation requires that '$homedirfolders' and
'$homedirspools' both be set to 'no' in NeoMail's configuration." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-3/advisory/" );
  # http://sourceforge.net/project/shownotes.php?release_id=392562&group_id=2874
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42e79545" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NeoMail version 1.29 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/14");
 script_cvs_date("$Date: 2013/01/24 17:54:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:neomail:neomail");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Loop through directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to add a folder.
  #
  # nb: we'll use a name that's too long so it will fail.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/neomail-prefs.pl?",
      "sessionid=nessus-session-0.", SCRIPT_NAME, "&",
      "action=addfolder&",
      "foldername=", rand_str(length:17)
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if ...
  #
  # nb: the error strings depend on the application's default
  #     language; adjust if it's not English.
  if (
    # the folder name is too long or...
    "<BR>Folder name cannot be more" >< res ||
    # we can't create the folder.
    "<BR>Can't create folder!<BR>" >< res
  ) {
    security_warning(port);
    exit(0);
  }
}
