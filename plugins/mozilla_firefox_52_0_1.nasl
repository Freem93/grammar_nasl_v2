#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99125);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

  script_cve_id("CVE-2017-5428");
  script_bugtraq_id(96959);
  script_osvdb_id(153959);
  script_xref(name:"MFSA", value:"2017-08");

  script_name(english:"Mozilla Firefox < 52.0.1 CreateImageBitmap RCE");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows host is
prior to 52.0.1. It is, therefore, affected by an integer overflow
condition in the nsGlobalWindow::CreateImageBitmap() function within
file dom/base/nsGlobalWindow.cpp due to improper validation of certain
input. An unauthenticated, remote attacker can exploit this to corrupt
memory, possibly resulting in the execution of arbitrary code.

Note that this function runs in the content sandbox, requiring a
second vulnerability to compromise a user's computer.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-08/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 52.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', fix:'52.0.1', severity:SECURITY_HOLE);
