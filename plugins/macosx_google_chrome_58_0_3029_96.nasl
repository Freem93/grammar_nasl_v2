#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99996);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/08 14:04:54 $");

  script_cve_id("CVE-2017-5068");
  script_bugtraq_id(98288);
  script_osvdb_id(156912);
  script_xref(name:"IAVB", value:"2017-B-0047");

  script_name(english:"Google Chrome < 58.0.3029.96 WebRTC Frame Order Handling Race Condition (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by an unspecified race condition.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS or Mac OS X
host is prior to 58.0.3029.96. It is, therefore, affected by an
unspecified race condition in the WebRTC component in frame_buffer2.cc
that is triggered during the handling of frame orders. An
unauthenticated, remote attacker can exploit this to have an
unspecified impact.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2017/05/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?46bdfe7b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 58.0.3029.96 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/05");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'58.0.3029.96', severity:SECURITY_HOLE);
