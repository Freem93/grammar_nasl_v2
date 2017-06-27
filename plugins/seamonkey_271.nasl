#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57921);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/09/17 11:05:43 $");

  script_cve_id("CVE-2012-0452");
  script_bugtraq_id(51975);
  script_osvdb_id(79216);

  script_name(english:"SeaMonkey < 2.7.1 Memory Corruption");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that is affected by a
memory corruption vulnerability.");
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.7.1.  Such
versions are potentially affected by a memory corruption
vulnerability. 

A use-after-free error exists in the method
'nsXBLDocumentInfo::ReadPrototypeBindings' and XBL bindings are not
properly removed from a hash table in the event of failure.  Clean up
processes may then attempt to use this data and cause application
crashes.  These application crashes are potentially exploitable.");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-10.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.7.1', severity:SECURITY_HOLE);