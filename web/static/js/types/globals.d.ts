// Type declarations for global variables and functions shared across browser scripts in SentinelNet

declare var globalDevices: any[];
declare var globalGroups: Record<string, any>;
declare var globalVendors: any[];
declare var globalVersions: Record<string, any>;
declare var currentLang: string;
declare var currentRole: string;
declare var currentUser: string;
declare var appLoading: boolean;
declare var i18n: Record<string, any>;
declare var _locView: any;
declare var _pingRefreshTimer: any;
declare var _activeSubnetScanJob: any;

declare var vis: any;
declare var html2pdf: any;

declare function apiFetch(url: string, options?: RequestInit): Promise<Response | null>;
declare function escapeHtml(str: any): string;
declare function showToast(msg: string, kind?: string): void;
declare function switchTab(tabId: string, clickedBtn?: HTMLElement): Promise<void>;
declare function appInit(): Promise<void>;

declare function renderDeviceTable(): void;
declare function renderGroupsTable(): void;
declare function loadSnmpDefaults(): Promise<void>;
declare function populateProvisioningFormSelects(): void;
declare function loadProvisioningTab(): void;
declare function loadHome(): void;
declare function loadTopology(): Promise<void>;
declare function loadInteractiveMap(): Promise<void>;
declare function loadCategoriesData(): void;
declare function loadThreatIntel(): void;
declare function locSwitchView(view: any): void;
declare function loadConfigAnalyzer(): void;
declare function loadAiTab(): void;
declare function loadUsers(): void;
declare function loadSites(): void;
declare function loadMcpTab(): void;
declare function loadMcpClientTab(): void;
declare function loadFgtTab(): void;
declare function loadWlcTab(): void;
declare function loadAuditChecklistTab(): void;
declare function loadAppSettings(): void;
declare function flowsTabShown(): void;
declare function loadIncidentsTab(): void;
declare function loadRedundancyTab(): void;
declare function loadNetSecAuditTab(): void;
declare function startTriageStatusPolling(): void;

declare function openCliModal(ip: string): void;
declare function openSubnetScanModal(): void;
declare function editDevice(ip: string): void;
declare function deleteDevice(ip: string): void;
declare function pingSingleDevice(ip: string, btn?: HTMLElement): void;
declare function triageSingleDevice(ip: string, btn?: HTMLElement): void;
declare function renameDevice(ip: string): void;
declare function downloadBackup(ip: string): void;
declare function renameGroup(group: string): void;
declare function deleteGroup(group: string): void;

interface Window {
  globalDevices: any[];
  globalGroups: Record<string, any>;
  globalVendors: any[];
  globalVersions: Record<string, any>;
  currentLang: string;
  currentRole: string;
  currentUser: string;
  appLoading: boolean;
  i18n: Record<string, any>;
  _activeSubnetScanJob: any;
  webkitAudioContext: typeof AudioContext;
}
