import { useEffect, useState } from 'react';
import SettingsButton from './components/settings';
import ProgressBar from './components/progressLoader';
import { Activity, FolderClock, MessageCircleWarning, RefreshCcw } from 'lucide-react';
import { processGraphData, RiskGauge, RiskGraph } from './components/history-graph';

type SourceStatus = 'Safe' | 'Suspicious' | 'Malicious' | string;

interface HistoryEntry {
  url: string;
  state: string;
  vulnerabilityScore: number;
  reportingSource: string;
  sources: Record<string, SourceStatus>;
  impact: string;
  errors?: string[];
}

interface AppSettings {
  blockHighRiskLinks: boolean;
}

function App() {
  const [progress, setProgress] = useState<number | null>(null);
  const [currentUrl, setCurrentUrl] = useState('');
  const [riskState, setRiskState] = useState('');
  const [scoreValue, setScoreValue] = useState<number | null>(null);
  const [reportingSource, setReportingSource] = useState('');
  const [sources, setSources] = useState<Record<string, SourceStatus>>({});
  const [impactMessage, setImpactMessage] = useState('');
  const [errors, setErrors] = useState<string[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [blockHighRiskLinks, setBlockHighRiskLinks] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [showRefreshButton, setShowRefreshButton] = useState<boolean>(false);

  // Initialize settings and data
  useEffect(() => {
    const updateUI = (keepLoading = false) => {
      if (!keepLoading) setIsLoading(false);

      browser.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const url = tabs[0]?.url || '';
        setCurrentUrl(url);

        browser.storage.local.get(['linkHistory'], (result) => {
          const linkHistory: HistoryEntry[] = result.linkHistory || [];
          setHistory(linkHistory);

          const currentEntry = linkHistory.find((entry) => entry.url === url);
          console.log(currentEntry)

          if (currentEntry) {
            setRiskState(currentEntry.state);
            setScoreValue(currentEntry.vulnerabilityScore);
            setReportingSource(currentEntry.reportingSource);
            setSources(currentEntry.sources);
            setImpactMessage(currentEntry.impact);
            setErrors(currentEntry.errors?.length ? currentEntry.errors : ['No errors detected. All checks completed successfully! 😊']);
          } else {
            setRiskState('Not yet analyzed');
            setScoreValue(null);
            setReportingSource('Not yet analyzed');
            setSources({});
            setImpactMessage('Please wait for analysis... 😊');
            setErrors([keepLoading ? 'Analysis in progress...' : 'Waiting for analysis to complete...']);
          }
        });
      });
    };

    // Load initial settings and state
    setTimeout(() => updateUI(false), 1000);

    // Get or initialize app settings
    browser.storage.local.get(['settings'], (result) => {
      const settings: AppSettings = result.settings || { blockHighRiskLinks: false };
      if (!result.settings) {
        browser.storage.local.set({ settings });
      }
      setBlockHighRiskLinks(settings.blockHighRiskLinks);
    });

    const handleMessage = (message: any) => {
      if (message.action === 'analysisStarted') {
        setIsLoading(true);
        setProgress(0);
        updateUI(true);
        setShowRefreshButton(true);
      } else if (message.action === 'progressUpdate') {
        setProgress(message.progress);
      } else if (message.action === 'historyUpdated') {
        updateUI(false);
      }
    };


    browser.runtime.onMessage.addListener(handleMessage);
    return () => browser.runtime.onMessage.removeListener(handleMessage);
  }, []);

  const handleRefresh = () => {
    setIsRefreshing(true);
    browser.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      if (!url) return;


      browser.runtime.sendMessage({ action: 'refreshAnalysis', url, tabId: tabs[0].id }, () => {
        setIsRefreshing(false);
      });
    });
  };

  const handleReportPhishing = () => {
    const submitUrl = `https://www.phishtank.com/add_web_phish.php?url=${encodeURIComponent(currentUrl)}`;
    browser.tabs.create({ url: submitUrl });
  };

  const handleCancelAnalysis = () => {
    browser.runtime.sendMessage({ action: 'cancelAnalysis' }, () => {
      setIsLoading(false);
    });
  };

  const riskStateToGuageScore = (state: String) => {
    switch (state) {
      case 'Safe':
        return 10;
      case 'Suspicious':
        return 50;
      case 'Phishing':
        return 95;
      default:
        return 0
    }
  }

  return (
    <div className='p-1'>
      <div className='flex items-center p-8 border border-separator rounded'>
        <div className='flex items-center flex-col w-[600px]'>
          <div className='flex items-center justify-between mb-3 w-full bg-backgroundLayer1 p-4 rounded'>
            <h1 className='text-3xl font-bold'>SEAD</h1>
            <div className='flex items-center gap-1 text-[10px]'>


              <span title="Analyze">
                <div
                  className='flex items-center space-x-1 cursor-pointer p-1 rounded-lg bg-[#36824347] text-systemGreen'
                  onClick={handleRefresh}>
                  <Activity />
                </div>
              </span>

              <span title="Clear History">
                <div
                  className='flex items-center space-x-1 cursor-pointer p-1 rounded-lg hover:bg-backgroundLayer2 text-systemBlue'
                  onClick={handleRefresh}>
                  <FolderClock />
                </div>
              </span>

              <span title='Settings'>
                <SettingsButton
                  blockHighRiskLinks={blockHighRiskLinks}
                  setBlockHighRiskLinks={(val) => {
                    setBlockHighRiskLinks(val);
                    browser.storage.local.set({ settings: { blockHighRiskLinks: val } });
                  }}
                />
              </span>
            </div>
          </div>


          {showRefreshButton && (<div className='w-full flex justify-start gap-6'>
            <div
              className='flex items-center space-x-1 cursor-pointer p-2 rounded-xl bg-backgroundLayer2 text-systemBlue hover:text-tintBlue hover:shadow-lg gap-2 shadow-lg text-[14px] mb-4'
              onClick={handleRefresh}>
              <div className={`${isRefreshing ? 'animate-spin' : ''}`}><RefreshCcw /></div>
              Refresh Analysis
            </div>
            {riskState && riskState !== 'Safe' && (<div
              className='flex items-center space-x-1 cursor-pointer p-2 rounded-xl bg-systemRed text-white hover:background-tintRed hover:shadow-lg gap-2 shadow-lg text-[14px] mb-4'
              onClick={handleReportPhishing}>
              <MessageCircleWarning />
              Report URL
            </div>)}
          </div>)
          }

          <div className='flex text-xl font-bold justify-start w-full mb-4'>{currentUrl}</div>

          <div className={`w-full h-[400px] overflow-y-auto pr-2 ${isLoading ? 'flex justify-center items-center' : ''}`}>
            {isLoading ? (
              typeof progress === 'number' && <ProgressBar value={progress} />
            ) : (
              <div className='flex flex-col justify-start w-full'>
                <div>

                </div>
                <div className="flex gap-4">
                  <div className='border border-separator p-4 rounded-lg shadow-lg mb-4 text-2l'>
                    {riskState && (
                      <>
                        <div className='grid grid-cols-2 gap-2'>
                          <div className='font-semibold'>Risk</div>
                          <div>{riskState}</div>
                        </div>
                        <div className='my-2 h-px w-full bg-separator' />
                      </>
                    )}

                    {scoreValue !== null && (
                      <>
                        <div className='grid grid-cols-2 gap-2'>
                          <div className='font-semibold'>Score</div>
                          <div>{riskStateToGuageScore(riskState)}%</div>
                        </div>
                        <div className='my-2 h-px w-full bg-separator' />
                      </>
                    )}

                    {reportingSource && (
                      <>
                        <div className='grid grid-cols-2 gap-2'>
                          <div className='font-semibold'>Primary Source</div>
                          <div>{reportingSource}</div>
                        </div>
                        <div className='my-2 h-px w-full bg-separator' />
                      </>
                    )}

                    <p className='mt-4'>{impactMessage}</p>
                  </div>

                  {scoreValue !== null && (
                    <RiskGauge score={riskStateToGuageScore(riskState)} />
                  )}
                </div>




                <div className='w-full justify-start mb-4 mt-4'>
                  <div className='mb-2 text-xl font-semibold'>Sources Results</div>
                  <ul>
                    {history.length > 0 && (
                      <li>
                        <div className="overflow-x-auto">
                          <table className="min-w-full text-sm text-left border border-separator rounded-lg shadow-lg p-4">
                            <thead className="bg-backgrounLayer1 uppercase tracking-wide">
                              <tr>
                                <th className="px-4 py-2">Source</th>
                                <th className="px-4 py-2">Status</th>
                              </tr>
                            </thead>
                            <tbody>
                              {Object.entries(history[0].sources).map(([source, status]) => (
                                <tr key={source} className="border-t border-separator">
                                  <td className="px-4 py-2 font-medium capitalize">{source}</td>
                                  <td className="px-4 py-2">
                                    <span className={`px-2 py-1 rounded-lg w-[100px] justify-center text-xs font-semibold 
                ${status === 'Suspicious' ? 'text-systemYellow border border-systemYellow' :
                                        status === 'Malicious' || status === 'Phishing' ? 'border border-systemRed text-systemRed' :
                                          status === 'Safe' ? 'border border-systemGreen text-systemGreen' :
                                            'border border-gray1 text-gray1'
                                      }`}>
                                      {status}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </li>

                    )
                    }
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
