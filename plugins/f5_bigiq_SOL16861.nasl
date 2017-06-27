#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85693);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/31 14:21:56 $");

  script_cve_id("CVE-2015-4637");
  script_bugtraq_id(75943);
  script_osvdb_id(124885);

  script_name(english:"F5 Networks BIG-IQ REST API Authentication Bypass (SOL16861)");
  script_summary(english:"Checks BIG-IQ version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote F5 Networks BIG-IQ device
is affected by an authentication bypass vulnerability due to a flaw in
the REST API. An unauthenticated, remote attacker can exploit this to
obtain an authentication token for arbitrary LDAP user accounts when
the device is configured to use LDAP remote authentication and the
LDAP server allows anonymous BIND operations.");
  # https://support.f5.com/kb/en-us/solutions/public/16000/800/sol16861.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7aa2ed3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to F5 Networks BIG-IQ version 4.4.0 HF2 / 4.5.0 HF2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-iq");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-iq_cloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-iq_device");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-iq_security");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-iq_adc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("f5_bigiq_detect.nbin");
  script_require_keys("Host/BIG-IQ/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ssh_func.inc");

version = get_kb_item_or_exit("Host/BIG-IQ/version");
hotfix  = get_kb_item_or_exit("Host/BIG-IQ/hotfix");

# Even if LDAP is configured, the LDAP server 
# has to also allow anonymous binds, there is 
# no way to check for this. 
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = FALSE;
if (version =~ "^4\.4(\.|$)" && int(hotfix) < 2)
  fix = "4.4.0 HF2";
else if(version =~ "^4\.5(\.|$)" && int(hotfix) < 2)
  fix = "4.5.0 HF2";
else
  audit(AUDIT_INST_VER_NOT_VULN, "BIG-IQ", version);

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "BIG-IQ", version);
