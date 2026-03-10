export module mcpplibs.tinyhttps:sse;

import std;

namespace mcpplibs::tinyhttps {

export struct SseEvent {
    std::string event;      // event type (default "message")
    std::string data;       // event data
    std::string id;         // event id (optional)
};

export class SseParser {
private:
    std::string buffer_;
    std::string currentEvent_;
    std::string currentData_;
    std::string currentId_;

public:
    std::vector<SseEvent> feed(std::string_view chunk) {
        buffer_.append(chunk);
        std::vector<SseEvent> events;

        // Scan for event boundaries: \n\n or \r\n\r\n
        while (true) {
            // Find double newline (event boundary)
            auto pos = find_event_boundary_();
            if (pos == std::string::npos) {
                break;
            }

            // Extract the event block
            std::string_view block(buffer_.data(), pos);
            // Determine how many chars to skip past the boundary
            std::size_t skip = 0;
            if (pos + 1 < buffer_.size() && buffer_[pos] == '\n' && buffer_[pos + 1] == '\n') {
                skip = pos + 2;
            } else if (pos + 3 < buffer_.size() &&
                       buffer_[pos] == '\r' && buffer_[pos + 1] == '\n' &&
                       buffer_[pos + 2] == '\r' && buffer_[pos + 3] == '\n') {
                skip = pos + 4;
            } else {
                skip = pos + 2; // fallback for \n\n
            }

            // Process each line in the block
            process_block_(block);
            dispatch_event_(events);

            buffer_.erase(0, skip);
        }

        return events;
    }

    void reset() {
        buffer_.clear();
        currentEvent_.clear();
        currentData_.clear();
        currentId_.clear();
    }

private:
    std::size_t find_event_boundary_() const {
        for (std::size_t i = 0; i < buffer_.size(); ++i) {
            if (buffer_[i] == '\n' && i + 1 < buffer_.size() && buffer_[i + 1] == '\n') {
                return i;
            }
            if (buffer_[i] == '\r' && i + 3 < buffer_.size() &&
                buffer_[i + 1] == '\n' && buffer_[i + 2] == '\r' && buffer_[i + 3] == '\n') {
                return i;
            }
        }
        return std::string::npos;
    }

    void process_block_(std::string_view block) {
        while (!block.empty()) {
            // Find end of line
            std::size_t lineEnd = 0;
            std::size_t skip = 0;
            bool found = false;
            for (std::size_t i = 0; i < block.size(); ++i) {
                if (block[i] == '\r' && i + 1 < block.size() && block[i + 1] == '\n') {
                    lineEnd = i;
                    skip = i + 2;
                    found = true;
                    break;
                }
                if (block[i] == '\n') {
                    lineEnd = i;
                    skip = i + 1;
                    found = true;
                    break;
                }
            }
            if (!found) {
                lineEnd = block.size();
                skip = block.size();
            }

            process_line_(block.substr(0, lineEnd));
            block = block.substr(skip);
        }
    }

    void process_line_(std::string_view line) {
        if (line.empty()) {
            return;
        }

        // Comment line
        if (line[0] == ':') {
            return;
        }

        // Find colon
        auto colonPos = line.find(':');
        if (colonPos == std::string_view::npos) {
            // Field with no value — treat field name as the whole line, value as empty
            return;
        }

        auto field = line.substr(0, colonPos);
        auto value = line.substr(colonPos + 1);

        // Strip single leading space from value if present
        if (!value.empty() && value[0] == ' ') {
            value = value.substr(1);
        }

        if (field == "data") {
            if (!currentData_.empty()) {
                currentData_ += '\n';
            }
            currentData_.append(value);
        } else if (field == "event") {
            currentEvent_ = std::string(value);
        } else if (field == "id") {
            currentId_ = std::string(value);
        }
        // Other fields ignored
    }

    void dispatch_event_(std::vector<SseEvent>& events) {
        if (currentData_.empty() && currentEvent_.empty() && currentId_.empty()) {
            return;
        }

        SseEvent ev;
        ev.event = currentEvent_.empty() ? "message" : std::move(currentEvent_);
        ev.data = std::move(currentData_);
        ev.id = std::move(currentId_);
        events.push_back(std::move(ev));

        currentEvent_.clear();
        currentData_.clear();
        currentId_.clear();
    }
};

} // namespace mcpplibs::tinyhttps
