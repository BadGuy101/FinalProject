# utils/feature_aggregator.py

def aggregate_features(scan_result, system_metrics, network_data=None, security_data=None):
    """
    Combines features from multiple modules for ML input
    """
    features = [
        scan_result.get('file_size', 0),
        len(scan_result.get('detections', [])),
        scan_result.get('threat_level', 0),
        int(scan_result.get('is_malicious', False)),
        system_metrics.get('cpu_percent', 0),
        system_metrics.get('memory_percent', 0),
    ]
    
    if security_data:
        features.append(security_data.get('suspicious_processes', 0))
    else:
        features.append(0)

    if network_data:
        features.append(network_data.get('suspicious_connections', 0))
        features.append(network_data.get('total_traffic_bytes', 0))
    else:
        features.extend([0, 0])

    return features
