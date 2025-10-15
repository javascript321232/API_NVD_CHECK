import React, { useEffect, useState } from "react";
import axios from "axios";
import "./App.css";

function App() {
  const [cves, setCves] = useState([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [limit, setLimit] = useState(10);

  const backendURL = "http://127.0.0.1:8000";

  const fetchCves = async (p = page, l = limit) => {
    setLoading(true);
    try {
      const response = await axios.get(
        `${backendURL}/cves/list?page=${p}&limit=${l}`
      );
      setCves(response.data.data);
      setTotal(response.data.total);
      setPage(response.data.page);
    } catch (error) {
      console.error("Error fetching CVEs:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCves();
  }, []);

  const totalPages = Math.ceil(total / limit);

  const getStatusClass = (status) => {
    if (!status) return "status-default";
    switch (status.toUpperCase()) {
      case "HIGH":
        return "status-high";
      case "MEDIUM":
        return "status-medium";
      case "LOW":
        return "status-low";
      default:
        return "status-default";
    }
  };

  return (
    <div className="container">
      <h2>CVE List</h2>

      <table className="cve-table">
        <thead>
  <tr>
    <th>CVE ID</th>
    <th>IDENTIFIER</th>
    <th>PUBLISHED DATE</th>
    <th>LAST MODIFIED DATE</th>
    <th>BASE SEVERITY</th>
    <th>BASE SCORE</th>
    <th>STATUS</th>
  </tr>
</thead>

        <tbody>
          {loading ? (
            <tr>
              <td colSpan={5} className="table-message">Loading...</td>
            </tr>
          ) : cves.length === 0 ? (
            <tr>
              <td colSpan={5} className="table-message">No data found</td>
            </tr>
          ) : (
            cves.map((cve) => (
              <tr key={cve._id}>
  <td>{cve.id || cve.cve_id || cve._id}</td>
  <td>{cve.sourceIdentifier || "-"}</td>
  <td>{cve.published || cve.published_date || "-"}</td>
  <td>{cve.lastModified || cve.last_modified_date || "-"}</td>

  {/* Base Severity */}
  <td>
    <span
      className={`status-pill ${getStatusClass(
        cve.metrics?.cvssMetricV2?.[0]?.baseSeverity
      )}`}
    >
      {cve.metrics?.cvssMetricV2?.[0]?.baseSeverity || "-"}
    </span>
  </td>

  {/* Base Score */}
  <td>{cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? "-"}</td>

  {/* Vulnerability Status */}
  <td>
    <span className={`status-pill ${getStatusClass(cve.vulnStatus)}`}>
      {cve.vulnStatus || "-"}
    </span>
  </td>
</tr>

            ))
          )}
        </tbody>
      </table>

      <div className="pagination">
        <div>
          Results per page:{" "}
          <select
            value={limit}
            onChange={(e) => {
              const newLimit = parseInt(e.target.value);
              setLimit(newLimit);
              fetchCves(1, newLimit);
            }}
          >
            {[5,10,15, 20, 50, 100].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </div>

        <div className="page-buttons">
          <button disabled={page === 1} onClick={() => fetchCves(page - 1, limit)}>◀</button>

          {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => {
            if (p === 1 || p === totalPages || (p >= page - 2 && p <= page + 2)) {
              return (
                <button
                  key={p}
                  onClick={() => fetchCves(p, limit)}
                  className={p === page ? "active" : ""}
                >
                  {p}
                </button>
              );
            }
            if (p === page - 3 || p === page + 3) return <span key={p}>...</span>;
            return null;
          })}

          <button disabled={page === totalPages} onClick={() => fetchCves(page + 1, limit)}>▶</button>
        </div>

        <div>
          {`Showing ${page * limit - limit + 1} - ${Math.min(page * limit, total)} of ${total} records`}
        </div>
      </div>
    </div>
  );
}

export default App;
