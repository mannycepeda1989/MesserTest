/* eslint-disable @typescript-eslint/camelcase */
/* eslint-disable @typescript-eslint/no-var-requires */
const Sequelize  = require('sequelize');
const db = require("../../db/models");
const Op = Sequelize.Op;
const QueryTypes = db.sequelize.QueryTypes;

//DAST vulns active AND not remediated
exports.findDastVulnsNotRemediated = async (req, res) => {
    console.log("MATCH findDastVulnsNotRemediated");
    
    const rawQuery = "SELECT d.id, d.vendor_vuln_id AS vendor_id, d.first_found as vuln_date, d.last_found, d.times_found, d.severity, "
    + "d.date_remediated, d.remediation_user, d.remediation_note, d.\"deletedAt\", d.deleted_by, d.reason_deleted, v.name AS vendor, b.name AS business, "
    + "a.name AS application, a.owner AS owner_email "
    + "FROM appvulnmgmt.dast_vulnerabilities d "
    + "INNER JOIN appvulnmgmt.vendors v ON v.id = d.vendor_id "
    + "INNER JOIN appvulnmgmt.businesses b ON b.id = d.business_id "
    + "INNER JOIN appvulnmgmt.applications a ON a.id = d.application_id "
    + "WHERE d.\"deletedAt\" IS NULL "
    + "ORDER BY a.name, d.first_found"
  
    db.sequelize.query(
      rawQuery,
      {
        bind: { status: 'active' },
        type: QueryTypes.SELECT
      }
    )
    .then(data => {
      res.json(data);
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        message:
          err.message || "An error occurred in findDastVulnsNotRemediated."
      });
    });
};

//DAST vulns remediated monthly
exports.findDastVulnsRemediated = async (req, res) => {
    console.log("MATCH findDastVulnsRemediated");
    
    const rawQuery = "SELECT d.id, d.vendor_vuln_id AS vendor_id, d.first_found as vuln_date, d.last_found, d.times_found, d.severity, "
    + "d.date_remediated, d.remediation_user, d.remediation_note, d.\"deletedAt\", d.deleted_by, d.reason_deleted, v.name AS vendor, b.name AS business, "
    + "a.name AS application, a.owner AS owner_email "
    + "FROM appvulnmgmt.dast_vulnerabilities d "
    + "INNER JOIN appvulnmgmt.vendors v ON v.id = d.vendor_id "
    + "INNER JOIN appvulnmgmt.businesses b ON b.id = d.business_id "
    + "INNER JOIN appvulnmgmt.applications a ON a.id = d.application_id "
    + "WHERE d.date_remediated IS NOT NULL AND d.\"deletedAt\" IS NULL "
    + "ORDER BY a.name, d.first_found"
  
    db.sequelize.query(
      rawQuery,
      {
        bind: { status: 'active' },
        type: QueryTypes.SELECT
      }
    )
    .then(data => {
      res.json(data);
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        message:
          err.message || "Some error occurred in findDastVulnsRemediated."
      });
    });
};

//Custom vulns active AND not remediated
exports.findExtVulnsNotRemediated = async (req, res) => {
    console.log("MATCH findDastVulnsNotRemediated");
    
    const rawQuery = "SELECT cv.id, cv.report_vuln_id AS report_id, cvt.test_date as vuln_date, cv.severity, cv.date_remediated, "
    + "cv.remediation_user, cv.remediation_note, cv.\"deletedAt\", cv.deleted_by, cv.reason_deleted, v.name AS vendor, b.name AS business, a.name AS application, "
    + "a.owner AS owner_email "
    + "FROM appvulnmgmt.custom_vulnerabilities cv "
    + "LEFT OUTER JOIN appvulnmgmt.custom_vuln_tests cvt ON cv.test_id = cvt.id "
    + "INNER JOIN appvulnmgmt.vendors v ON v.id = cvt.vendor_id "
    + "INNER JOIN appvulnmgmt.businesses b ON b.id = cvt.business_id "
    + "INNER JOIN appvulnmgmt.applications a ON a.id = cvt.application_id "
    + "WHERE cv.\"deletedAt\" IS NULL "
    + "ORDER BY a.name, cvt.test_date"

    db.sequelize.query(
      rawQuery,
      {
        bind: { status: 'active' },
        type: QueryTypes.SELECT
      }
    )
    .then(data => {
      res.json(data);
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        message:
          err.message || "Some error occurred in findExtVulnsNotRemediated."
      });
    });
};

//External vulns remediated monthly
exports.findExtVulnsRemediated = async (req, res) => {
    console.log("MATCH findExtVulnsRemediated");
    
    const rawQuery = "select cv.id, cv.report_vuln_id as report_id, cvt.test_date as vuln_date, cv.severity, cv.date_remediated, "
    + "cv.remediation_user, cv.remediation_note, cv.\"deletedAt\", cv.deleted_by, cv.reason_deleted, v.name as vendor, b.name as business, a.name as application, "
    + "a.owner as owner_email "
    + "FROM appvulnmgmt.custom_vulnerabilities cv "
    + "LEFT OUTER JOIN appvulnmgmt.custom_vuln_tests cvt on cv.test_id = cvt.id "
    + "INNER JOIN appvulnmgmt.vendors v ON v.id = cvt.vendor_id "
    + "INNER JOIN appvulnmgmt.businesses b ON b.id = cvt.business_id "
    + "INNER JOIN appvulnmgmt.applications a ON a.id = cvt.application_id "
    + "WHERE cv.date_remediated is not null AND cv.\"deletedAt\" IS NULL "
    + "ORDER BY a.name, cvt.test_date"
     
    db.sequelize.query(
      rawQuery,
      {
        bind: { status: 'active' },
        type: QueryTypes.SELECT
      }
    )
    .then(data => {
      res.json(data);
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        message:
          err.message || "Some error occurred in findExtVulnsRemediated."
      });
    });
};

//SAST vulns active AND not remediated
exports.findSASTVulnsNotRemediated = async (req, res) => {
  console.log("MATCH findSASTVulnsNotRemediated");
  
  const rawQuery = "SELECT p.id, p.name as project, s.id, s.vendor_scan_id, sast.first_found as vuln_date, sast.date_remediated, sast.id, sast.state as \"state\", sast.name as sast_vuln_name, sast.severity "
  + " FROM appvulnmgmt.cx1_projects p "
  + " JOIN appvulnmgmt.cx1_scans s ON s.project_id = p.id "
  + " JOIN appvulnmgmt.cx1_sast_vulns sast ON sast.scan_id = s.id "
  + " WHERE sast.state != 'NOT_EXPLOITABLE' AND sast.date_remediated IS NULL "
  + " AND p.\"deletedAt\" IS NULL AND s.\"deletedAt\" IS NULL and sast.\"deletedAt\" IS NULL "
  + " AND s.vendor_scan_id = p.last_scan_id "
  + " ORDER BY s.vendor_scan_id, " 
  + "     CASE WHEN sast.severity = 'HIGH' THEN 0"
  + "          WHEN sast.severity = 'MEDIUM' THEN 1"
  + "          ELSE 2 END"

  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "Some error occurred in findSASTVulnsNotRemediated."
    });
  });
};

//SAST vulns remediated monthly
exports.findSASTVulnsRemediated = async (req, res) => {
  console.log("MATCH findSASTVulnsRemediated");
  
  const rawQuery = "SELECT p.id, p.name as project, s.id, s.vendor_scan_id, sast.first_found as vuln_date, sast.date_remediated, sast.id, sast.state as \"state\", sast.name as sast_vuln_name, sast.severity "
  + " FROM appvulnmgmt.cx1_projects p "
  + " JOIN appvulnmgmt.cx1_scans s ON s.project_id = p.id "
  + " JOIN appvulnmgmt.cx1_sast_vulns sast ON sast.scan_id = s.id "
  + " WHERE sast.state != 'NOT_EXPLOITABLE' AND sast.date_remediated IS NULL "
  + " AND p.\"deletedAt\" IS NULL AND s.\"deletedAt\" IS NULL AND sast.\"deletedAt\" IS NULL AND sast.date_remediated IS NOT NULL"
  + " AND s.vendor_scan_id = p.last_scan_id "
  + " ORDER BY s.vendor_scan_id, " 
  + "     CASE WHEN sast.severity = 'HIGH' THEN 0"
  + "          WHEN sast.severity = 'MEDIUM' THEN 1"
  + "          ELSE 2 END"
   
  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "Some error occurred in findSASTVulnsRemediated."
    });
  });
};

//IAC vulns active AND not remediated
exports.findIACVulnsNotRemediated = async (req, res) => {
  console.log("MATCH findIACVulnsNotRemediated");
  
  const rawQuery = "SELECT p.id, p.name as project, s.id, s.vendor_scan_id, iac.first_found as vuln_date, iac.date_remediated, iac.id, iac.state as \"state\", iac.name as iac_vuln_name, iac.severity "
  + " FROM appvulnmgmt.cx1_projects p "
  + " JOIN appvulnmgmt.cx1_scans s ON s.project_id = p.id "
  + " JOIN appvulnmgmt.cx1_iac_vulns iac ON iac.scan_id = s.id "
  + " WHERE iac.state != 'NOT_EXPLOITABLE' AND iac.date_remediated IS NULL "
  + " AND p.\"deletedAt\" IS NULL AND s.\"deletedAt\" IS NULL and iac.\"deletedAt\" IS NULL "
  + " AND s.vendor_scan_id = p.last_scan_id "
  + " ORDER BY s.vendor_scan_id, " 
  + "     CASE WHEN iac.severity = 'HIGH' THEN 0"
  + "          WHEN iac.severity = 'MEDIUM' THEN 1"
  + "          ELSE 2 END"

  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "Some error occurred in findIACVulnsNotRemediated."
    });
  });
};

//IAC vulns remediated monthly
exports.findIACVulnsRemediated = async (req, res) => {
  console.log("MATCH findIACVulnsRemediated");
  
  const rawQuery = "SELECT p.id, p.name as project, s.id, s.vendor_scan_id, iac.first_found as vuln_date, iac.date_remediated, iac.id, iac.state as \"state\", iac.name as iac_vuln_name, iac.severity "
  + " FROM appvulnmgmt.cx1_projects p "
  + " JOIN appvulnmgmt.cx1_scans s ON s.project_id = p.id "
  + " JOIN appvulnmgmt.cx1_iac_vulns iac ON iac.scan_id = s.id "
  + " WHERE iac.state != 'NOT_EXPLOITABLE' AND iac.date_remediated IS NULL "
  + " AND p.\"deletedAt\" IS NULL AND s.\"deletedAt\" IS NULL AND iac.\"deletedAt\" IS NULL AND iac.date_remediated IS NOT NULL"
  + " AND s.vendor_scan_id = p.last_scan_id "
  + " ORDER BY p.id, s.vendor_scan_id"
   
  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "Some error occurred in findIACVulnsRemediated."
    });
  });
};

//SCA vulns active AND not remediated
exports.findSCAVulnsNotRemediated = async (req, res) => {
  console.log("MATCH findSCAVulnsNotRemediated");
  
  const rawQuery = "SELECT p.id as pid, p.name as project, p.last_scan_date, p.project_creation_date, s.id as sid, s.vendor_scan_id, sca.id, sca.name as pkg, sca.version,"
  + " sca.high_vulns, sca.medium_vulns, sca.low_vulns "
  + " FROM appvulnmgmt.cx1_projects p "
  + " JOIN appvulnmgmt.cx1_scans s ON s.project_id = p.id "
  + " JOIN appvulnmgmt.cx1_sca_packages sca ON sca.scan_id = s.id "
  + " WHERE (sca.test_dep = false AND sca.development_dep = false AND sca.package_usage_type != 'UNUSED' AND sca.severity != 'NONE') AND sca.date_remediated IS NULL "
  + " AND p.\"deletedAt\" IS NULL AND s.\"deletedAt\" IS NULL and sca.\"deletedAt\" IS NULL "
  + " AND s.vendor_scan_id = p.last_scan_id "
  + " ORDER BY p.id, s.vendor_scan_id"

  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "Some error occurred in findSCAVulnsNotRemediated."
    });
  });
};

//SCA vulns remediated monthly
exports.findSCAVulnsRemediated = async (req, res) => {
  console.log("MATCH findSCAVulnsRemediated");
  
  const rawQuery = "SELECT p.id as pid, p.name as project, p.last_scan_date, p.project_creation_date, s.id as sid, s.vendor_scan_id, sca.id, sca.name as pkg, sca.version, "
  + " sca.high_vulns, sca.medium_vulns, sca.low_vulns "
  + " FROM appvulnmgmt.cx1_projects p "
  + " JOIN appvulnmgmt.cx1_scans s ON s.project_id = p.id "
  + " JOIN appvulnmgmt.cx1_sca_packages sca ON sca.scan_id = s.id "
  + " WHERE (sca.test_dep = false AND sca.development_dep = false AND sca.package_usage_type != 'UNUSED' AND sca.severity != 'NONE') AND sca.date_remediated IS NOT NULL "
  + " AND p.\"deletedAt\" IS NULL AND s.\"deletedAt\" IS NULL and sca.\"deletedAt\" IS NULL "
  + " AND s.vendor_scan_id = p.last_scan_id "
  + " ORDER BY s.vendor_scan_id, " 
  + "     CASE WHEN sca.severity = 'HIGH' THEN 0"
  + "          WHEN sca.severity = 'MEDIUM' THEN 1"
  + "          ELSE 2 END"

  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "Some error occurred in findSCAVulnsRemediated."
    });
  });
};

//External vulns remediated monthly
exports.findLambdaRTVulnsNotRemediated = async (req, res) => {
  console.log("MATCH findLambdaRTVulnsNotRemediated");
  
  const rawQuery = "select lv.lambda_id, ls.name, ls.account_name, ls.highest_severity, ls.\"createdAt\" as vuln_date, lv.severity, lv.date_remediated " +
  "FROM appvulnmgmt.lambda_rt_vulns lv " + 
  "LEFT OUTER JOIN appvulnmgmt.lambda_rts ls on lv.lambda_id = ls.id " +
  "WHERE ls.\"deletedAt\" IS NULL"
   
  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "An error occurred in findLambdaRTVulnsNotRemediated."
    });
  });
};

//External vulns remediated monthly
exports.findLambdaRTVulnsRemediated = async (req, res) => {
  console.log("MATCH findLambdaRTVulnsRemediated");
  
  const rawQuery = "select lv.id, ls.name, ls.account_name, ls.\"createdAt\" as vuln_date, lv.severity, lv.date_remediated " +
  "FROM appvulnmgmt.lambda_rt_vulns lv " + 
  "LEFT OUTER JOIN appvulnmgmt.lambda_rts ls on lv.lambda_id = ls.id " +
  "WHERE lv.date_remediated is not null AND ls.\"deletedAt\" IS NULL " +
  "ORDER BY ls.account_name"
   
  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "Some error occurred in findLambdaRTVulnsRemediated."
    });
  });
};

exports.findImageRTVulnsNotRemediated = async (req, res) => {
  console.log("MATCH findImageRTVulnsNotRemediated");
  
  const rawQuery = "select iv.image_id, i.name, i.account_name, i.highest_severity, i.image_created as vuln_date, iv.severity, iv.date_remediated " +
  "FROM appvulnmgmt.image_rt_vulns iv " + 
  "LEFT OUTER JOIN appvulnmgmt.image_rts i on iv.image_id = i.id " +
  "WHERE i.\"deletedAt\" IS NULL"
   
  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "An error occurred in findImageRTVulnsNotRemediated."
    });
  });
};

//External vulns remediated monthly
exports.findImageRTVulnsRemediated = async (req, res) => {
  console.log("MATCH findImageRTVulnsRemediated");
  
  const rawQuery = "select iv.id, i.name, i.account_name, i.image_created as vuln_date, iv.severity, iv.date_remediated " +
  "FROM appvulnmgmt.image_rt_vulns iv " + 
  "LEFT OUTER JOIN appvulnmgmt.image_rts i on iv.image_id = i.id " +
  "WHERE iv.date_remediated is not null AND i.\"deletedAt\" IS NULL " +
  "ORDER BY i.cluster_name"
   
  db.sequelize.query(
    rawQuery,
    {
      bind: { status: 'active' },
      type: QueryTypes.SELECT
    }
  )
  .then(data => {
    res.json(data);
  })
  .catch(err => {
    console.log(err);
    res.status(500).json({
      message:
        err.message || "Some error occurred in findImageRTVulnsRemediated."
    });
  });
};
