#TRUSTED 21d8af2b246de3288a63f7d98b3ed508315118cbd1648c3b221da0a53cd86dfad38b4d19349315f62934128cce575942dc54226260337765c46697869db60c25d6b27ffbb9d3d23e5eb355f758d5299542db7802498e0465f790daf56c42573f0f2a4b5f565bd0636c26c81cf4b36843791d651d7754b5e8d042a085bf0c43436954527b049bed871ec240ea93f94cdff307051e728afd6464e16ccd2919c09f19919fdf196755a2aeab2d69fd99da145bb5ae8c514a80421df48538c9be709d57eb1e1473eb8c7878fafa952719dd750fa7ca16999a8c03f66ac826ff3799b70e885ac22ecc52165cb7d4052083a8424690735d0522a112da7445d37acfe466367261c09e8c0bdd0a9fc108aea9a8e46b94958a3bfd1e538e3729c04205c2c94b77ef65c62eca935f9b2315fd33a47a6f2156bd781b638361c90088b17dce08b5821e07d3e6a165738918f6b491c727d6446b3ca53c59f44fb8f057cd5b52c287c7f3ef7223b4d87fca372e71c837d2e877680a8ac300741ff078032cd73ae03c84eb8c3fcdc17a228883ca95e635dfdd5d10c4082e2557a243695864d39f4b2db3ab64028037792b68a50569879963db534d70c3bfd41096a39ba254769e7705afacee1bad7916128ff3dcc873af1c01bae559ce345fa9fff007dc3003dd7040bfc8d816474a6b371177fcc5ecd80ba4f335c2b46b63304aaab5e613c8bf51
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90357);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/06");

  script_cve_id("CVE-2016-1366");
  script_osvdb_id(136249);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw75848");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-ncs");

  script_name(english:"Cisco IOS XR SCP and SFTP Modules DoS (cisco-sa-20160323-ncs)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XR software
running on the remote device is affected by a denial of service
vulnerability in the Secure Copy Protocol (SCP) and Secure FTP (SFTP)
modules due to insecure permissions on certain files. An
authenticated, remote attacker can exploit this to overwrite system
files, resulting in a denial of service.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ncs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fc8f969");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuw75848.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

cbi = "CSCuw75848";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

# Since we cannot properly check the model, only run when paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if( version =~ "^5\.0\.[01]([^0-9]|$)" ) flag = 1;
if( version =~ "^5\.2\.[1345]([^0-9]|$)" ) flag = 1;

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + version +
      '\n';

    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
