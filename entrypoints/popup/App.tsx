import { useEffect, useState } from 'react';
import SettingsButton from './components/settings';
import ProgressBar from './components/progressLoader';
import { FolderClock, RefreshCcw } from 'lucide-react';
import { processGraphData, RiskGraph } from './components/history-graph';

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
    browser.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      if (!url) return;

      setIsLoading(true);
      browser.runtime.sendMessage({ action: 'refreshAnalysis', url, tabId: tabs[0].id }, () => {
        setIsLoading(false);
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

  return (
    <div className='p-1'>
      <div className='flex items-center p-8 border border-separator rounded'>
        <div className='flex items-center flex-col w-[600px]'>
          <div className='flex items-center justify-between mb-3 w-full bg-backgroundLayer1 p-4 rounded'>
            <h1 className='text-3xl font-bold'>SEAD</h1>
            <div className='flex items-center gap-1 text-[10px]'>
              <span title="Clear History">
                <div
                  className='flex items-center space-x-1 cursor-pointer p-1 rounded-lg hover:bg-backgroundLayer2 text-systemBlue'
                  onClick={handleRefresh}>
                  <FolderClock />
                </div>
              </span>
              <span title="Refresh Analysis">
                <div
                  className='flex items-center space-x-1 cursor-pointer p-1 rounded-lg hover:bg-backgroundLayer2 text-systemBlue'
                  onClick={handleRefresh}>
                  <RefreshCcw />
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

          <div className='flex text-xl font-bold justify-start w-full mb-4'>{currentUrl}</div>

          <div className={`w-full h-[400px] overflow-y-auto pr-2 ${isLoading ? 'flex justify-center items-center' : ''}`}>
            {isLoading ? (
              typeof progress === 'number' && <ProgressBar value={progress} />
            ) : (
              <div className='flex flex-col justify-start w-full'>
                <div>

                </div>
                <div className='border border-separator p-4 rounded-lg shadow-lg mb-4'>
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
                        <div>{scoreValue}%</div>
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

                {!isLoading && history.length > 0 && (
                  <RiskGraph data={processGraphData(history)} />
                )}


                <div className='w-full justify-start mb-4'>
                  <ul>
                    {history.map((entry, i) => {
                     // console.log(entry)
                      return (
                        <li key={i}>
                          <div className="overflow-x-auto">
                            <table className="min-w-full text-sm text-left border border-separator rounded-lg shadow-lg p-4">
                              <thead className="bg-backgrounLayer1 uppercase tracking-wide">
                                <tr>
                                  <th className="px-4 py-2">Source</th>
                                  <th className="px-4 py-2">Status</th>
                                </tr>
                              </thead>
                              <tbody>
                                {Object.entries(entry.sources).map(([source, status]) => (
                                  <tr key={source} className="border-t border-separator">
                                    <td className="px-4 py-2 font-medium capitalize">{source}</td>
                                    <td className="px-4 py-2">
                                      <span className={`px-2 py-1 rounded-lg w-[100px] justify-center text-xs font-semibold 
                                      ${status === 'Suspicious' ? 'text-systemYellow border border-systemYellow' :
                                          status === 'Malicious' ? 'border border-systemRed text-systemRed' :
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
                      );
                    })}
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
