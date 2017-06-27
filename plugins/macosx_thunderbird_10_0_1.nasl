#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58071);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/17 11:05:42 $");

  script_cve_id("CVE-2012-0452");
  script_bugtraq_id(51975);
  script_osvdb_id(79216);

  script_name(english:"Thunderbird 10.x < 10.0.1 Memory Corruption (Mac OS X)");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an email client that is potentially
affected by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 10.x is earlier than 10.0.1 and
is, therefore, potentially affected by a memory corruption
vulnerability. 

A use-after-free error exists in the method
'nsXBLDocumentInfo::ReadPrototypeBindings' and XBL bindings are not
properly removed from a hash table in the event of failure.  Clean-up
processes may then attempt to use this data and cause application
crashes.  These application crashes are potentially exploitable.");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-10.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 10.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

mozilla_check_version(product:'thunderbird', version:version, path:path, fix:'10.0.1', severity:SECURITY_HOLE);