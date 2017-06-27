#TRUSTED a6edf3ac73752cee7332fa115c2776b8f903bd5135b421bd7200c8c46c878b6ae0ff3ec6c7dfd5548abe9d5522f732e5096ce68e6bb172c1e7ec3c9dea73c4eba99a522d609c51d321d6ddc252ebf41648a8cfe28b5507de283fa87732be522e642799311d703becb1d5c782513a1b7230b63b3551038cc11c94cb36451b139b1c18dcf20a5540ab038981ee0af2152efab7dbe86cda3d6922a681edaad0f5ede151bdf385ac84d54f2f21d465996f8794e0b6dbe3c9a9499b3cf6db21849da7da42e4b6efe9a1712b7607b74a542a0ed2ce62966ad603b91e58f8f0e33c6d6e43af767cb94fca6bd65424909c7a7f6872f6a462a9b74cf28474cf47c2ca91924ed2e8a65a5323ada6d6766d9a9f25178ad4767aa230f3201ac24dd25cf2d0d1f5655654e7067f620bfd24ca29963505a0f4115333ce066029bc1541381e1e3ef48aa1ab76a2cc6aff0092c8e80b0b92e08ff93947561bc3941327c06f3ce90ec8156bc8b912646810e603f83e9e9e78f66a22b8d66d6a950391751ae6a8513b21201e0099b9126e78a1f5f26b9ff196a4355a75bfa09ef1a445b533293db2f2c72c54fe9af790017a19e47af6d288921528ab2ab8a4dac8d0e219cbf1c5c8d6a5647ae113347acb41a2c2a6e76b596b8fbefe2d71dce3d3942a2520b51205519e286bad0d91bb00703d146981bac232de3495d837c6fa322b24408187724311
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60020);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/05");
 
  script_name(english:"PCI DSS Compliance : Handling False Positives");
  script_summary(english:"How to handle false positives in PCI DSS scans.");

  script_set_attribute(attribute:"synopsis", value:
    "Notes the proper handling of false positives in PCI DSS scans."
  );
  script_set_attribute(attribute:"description", value:
"Note that per PCI Security Standards Council (PCI SSC) standards, if
the version of the remote software is known to contain flaws, a
vulnerability scanner must report it as vulnerable. The scanner must
still flag it as vulnerable, even in cases where a workaround or
mitigating configuration option is in place. This will result in the
scanner issuing false positives by PCI SSC design.

It is recommended that any workarounds and mitigating configurations
that are in place be documented including technical details, to be
presented to a third-party PCI auditor during an audit."
  );
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"risk_factor", value:"None");
 
  script_end_attributes();
 
  script_category(ACT_END); 
 
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Policy Compliance");
 
  script_dependencies("pci_remote_services.nasl");
 
  exit(0);
}

include("audit.inc");

if ( ! get_kb_item("Settings/PCI_DSS" )) audit(AUDIT_PCI);

if ( defined_func("nessus_get_dir") && file_stat(nessus_get_dir(N_STATE_DIR) + "/msp") > 0 )
{
  if ( hexstr(MD5(fread(nessus_get_dir(N_STATE_DIR) + "/msp"))) == "bcc7b34f215f46e783987c5f2e6199e5" )
    MSP = TRUE;
}

if ( ! MSP ) 
  security_note(port:0);
else exit(0, "This plugin does not run in the MSP configuration.");
