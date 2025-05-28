import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, CartesianGrid, Legend, Cell } from 'recharts';

export const processGraphData = (history: any[]) => {
    return history.map(entry => ({
        url: entry.url,
        timestamp: new Date(entry.timestamp).toLocaleString(),
        vulnerabilityScore: entry.vulnerabilityScore || 0,
        state: entry.state || 'Unknown'
    }));
};

export const RiskGraph = ({ data }: { data: any[] }) => {
    return (
        <div className="w-full h-[300px] mb-4 p-4 border border-separator rounded-lg shadow-lg">
            <h2 className="text-xl font-semibold mb-2">Site Risk History</h2>
            <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="timestamp" tick={{ fontSize: 10 }} />
                    <YAxis />
                    <Tooltip contentStyle={{ fontSize: '12px' }} />
                    <Legend />
                    <Bar
                        dataKey="vulnerabilityScore"
                        name="Score"
                        fill="#8884d8"
                        label={{ position: 'top', fontSize: 10 }}
                        isAnimationActive={true}
                    >
                        {data.map((entry, index) => (
                            <Cell
                                key={`cell-${index}`}
                                fill={
                                    entry.state === 'Safe'
                                        ? '#28a745'
                                        : entry.state === 'Suspicious'
                                            ? '#ffc107'
                                            : entry.state === 'Malicious'
                                                ? '#dc3545'
                                                : '#6c757d'
                                }
                            />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
};
