#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56125);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/13 21:35:39 $");

  script_name(english:"Google Chrome < 13.0.782.220 Untrusted CA");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that has support for an
untrustworthy certificate authority.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 13.0.782.220.  Due to a recent attack against certificate authority
DigiNotar, Google has added explicit distrust to the DigiNotar root
certificate and several intermediates in this version of Google Chrome. 

Note this is a further fix to the Google Chrome 13.0.782.218 fix, which
removed the DigiNotar root certificate.");
  # http://googlechromereleases.blogspot.com/2011/09/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?221de82d");
  script_set_attribute(attribute:"see_also", value:"http://codereview.chromium.org/7795014");

  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 13.0.782.220 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'13.0.782.220', severity:SECURITY_WARNING);
