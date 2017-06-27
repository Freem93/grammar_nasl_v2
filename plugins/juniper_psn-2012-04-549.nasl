#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58878);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/08/28 13:51:52 $");
  script_osvdb_id(82822);

  script_name(english:"Juniper Junos Key Generation Weakness (PSN-2012-04-549)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device generates weak cryptographic keys."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version and model number, the remote
Junos device generates weak cryptographic keys for SSL and SSH.  Due
to a lack of entropy in the initial certificate creation, duplicate
keys may be created on multiple devices.  An attacker with knowledge
of these keys would allow a man in the middle attacker to decrypt SSL
or SSH traffic.

Note that self-signed SSL certificates are affected, while SSL
certificates signed by a trusted certificate authority are not."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-04-549&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2ca6f92");
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-07-638&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68a256ed");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-04-549.  After upgrading, all self-signed SSL certificates
and SSH public/private keys need to be regenerated."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/25");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");
include("audit.inc");

fixes['10.4'] = '10.4R4';
fixes['11.1'] = '11.1R2';
fixes['11.2'] = '11.2R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

if (
  model != 'SRX100' &&
  model != 'SRX110' &&
  model != 'SRX210' &&
  model != 'SRX220' &&
  model != 'SRX240' &&
  model != 'SRX550' &&
  model != 'SRX650' &&
  model != 'LN1000'
)
{
  audit(AUDIT_HOST_NOT, 'SRX Series for the Branch or Mobile Secure Router');
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);

