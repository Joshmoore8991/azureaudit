<!-- Add these sections to your sentinel.html file -->

<!-- 1. DCR Upload Section - Add this AFTER your existing file upload section -->
<div class="row mb-4" id="dcrUploadSection">
  <div class="col-md-4">
    <label class="form-label fw-bold">
      <i class="bi bi-gear"></i> Upload DCR Configuration (Optional)
    </label>
    <div class="file-input-wrapper">
      <input type="file" id="dcrFileInput" accept=".json">
      <label for="dcrFileInput" class="file-input-label">
        <i class="bi bi-diagram-2"></i>
        <span id="dcrFileInputText">Choose DCR JSON file</span>
      </label>
    </div>
    <small class="text-muted">
      <i class="bi bi-info-circle"></i> 
      Analyze DCR transformations and identify Auxiliary Logs candidates for cost optimization
    </small>
  </div>
  <div class="col-md-2">
    <div class="stats-card" style="background: linear-gradient(135deg, #17a2b8, #138496);">
      <div class="stats-number" id="transformedTablesCount">0</div>
      <div class="stats-label">Transformed</div>
    </div>
  </div>
  <div class="col-md-2">
    <div class="stats-card" style="background: linear-gradient(135deg, #fd7e14, #e8590c);">
      <div class="stats-number" id="auxiliaryLogsCandidates">0</div>
      <div class="stats-label">Aux Logs</div>
    </div>
  </div>
  <div class="col-md-2">
    <div class="stats-card" style="background: linear-gradient(135deg, #28a745, #1e7e34);">
      <div class="stats-number" id="estimatedAuxSavings">$0</div>
      <div class="stats-label">Est. Savings</div>
    </div>
  </div>
  <div class="col-md-2">
    <div class="stats-card" style="background: linear-gradient(135deg, #6f42c1, #5a32a3);">
      <div class="stats-number" id="dcrStatus">None</div>
      <div class="stats-label">DCR Status</div>
    </div>
  </div>
</div>

<!-- 2. Enhanced Action Buttons - REPLACE your existing "analyzeDCR" button or add if missing -->
<button id="analyzeDCR" class="btn btn-primary btn-custom me-2" disabled>
  <i class="bi bi-diagram-2"></i> DCR + Aux Logs Analysis
</button>

<!-- 3. Enhanced Legend - REPLACE your existing legend section -->
<div class="enhanced-legend">
  <h6><i class="bi bi-info-circle"></i> Enhanced Cost Analysis Legend</h6>
  <div class="row">
    <div class="col-md-6">
      <div class="legend-row">
        <div class="legend-color" style="background-color: var(--success-color);"></div>
        <span>Available (Paid)</span>
      </div>
      <div class="legend-row">
        <div class="legend-color" style="background-color: var(--free-color);"></div>
        <span>Free Ingestion</span>
      </div>
      <div class="legend-row">
        <div class="legend-color" style="background-color: var(--e5-color);"></div>
        <span>E5 License Benefit</span>
      </div>
    </div>
    <div class="col-md-6">
      <div class="legend-row">
        <div class="transformation-indicator high-reduction"></div>
        <span>DCR Transformation (High Reduction)</span>
      </div>
      <div class="legend-row">
        <div class="auxiliary-logs-indicator aux-high-priority">AUX</div>
        <span>Auxiliary Logs Candidate</span>
      </div>
      <div class="legend-row">
        <div class="legend-color" style="background-color: var(--danger);"></div>
        <span>Not Available</span>
      </div>
    </div>
  </div>
</div>

<!-- 4. Update Script Loading Order - ADD these new scripts BEFORE your existing app.js -->
<script>
// Mark script loading for diagnostics
if (typeof window.scriptsLoaded === 'undefined') {
  window.scriptsLoaded = {};
}
</script>

<!-- Enhanced DCR and Auxiliary Logs scripts -->
<script src="./js/components/auxiliary-logs-analyzer.js"></script>
<script>window.scriptsLoaded['auxiliary-logs-analyzer'] = true;</script>

<script src="./js/components/enhanced-dcr-analyzer.js"></script>
<script>window.scriptsLoaded['enhanced-dcr-analyzer'] = true;</script>

<!-- Your existing scripts continue as normal -->
<!-- ... existing script tags ... -->

<!-- 5. Optional: Add Enhanced Cost Analysis Dashboard Section -->
<!-- Replace or enhance your existing cost analysis section -->
<div class="cost-analysis">
  <h4 class="mb-3">
    <i class="bi bi-piggy-bank"></i> Enhanced Cost Analysis Dashboard
    <small class="text-muted">Transformations & Auxiliary Logs</small>
  </h4>
  <div class="cost-breakdown">
    <div class="cost-item">
      <div class="cost-value" id="freeIngestionValue">0</div>
      <div>Free Ingestion Sources</div>
    </div>
    <div class="cost-item">
      <div class="cost-value" id="e5BenefitValue">0</div>
      <div>E5 Benefit Sources</div>
    </div>
    <div class="cost-item">
      <div class="cost-value" id="paidSourcesValue">0</div>
      <div>Paid Sources</div>
    </div>
    <div class="cost-item" style="background: linear-gradient(135deg, #17a2b8, #138496);">
      <div class="cost-value" id="auxLogsValue" style="color: white;">0</div>
      <div style="color: white;">Aux Logs Candidates</div>
    </div>
    <div class="cost-item">
      <div class="cost-value" id="totalSavingsValue">$0</div>
      <div>Est. Monthly Savings</div>
    </div>
  </div>
</div>
