#ifndef SHARE_UTILITIES_PMOVE_HPP
#define SHARE_UTILITIES_PMOVE_HPP


#include "utilities/growableArray.hpp"

template <typename Reg, typename TempFn, typename MoveFn>
class ParallelMover {
  GrowableArrayView<Reg> * _src;
  GrowableArrayView<Reg> * _dst;
  TempFn _tmp;
  MoveFn _move;

public:

  ParallelMover(GrowableArrayView<Reg> *src,
                GrowableArrayView<Reg> *dst,
                TempFn tmp,
                MoveFn move)
    : _src(src), _dst(dst), _tmp(tmp), _move(move),
      _n(src->length()) {
    assert(_src->length() == _dst->length(), "mismatch");
    GrowableArray<Status> _status(_n, _n, ToMove);
  }

  enum Status { ToMove, BeingMoved, Moved };

  const int _n;
  GrowableArray<Status> *_status = new GrowableArray<Status>(_n, _n, ToMove);

  // Recursive, like the original: emitting `dst->at(i) = _src->at(i)`
  // first requires clearing every j that still needs to read the
  // register dst->at(i) is about to clobber.
  void move_one(size_t i) {
    if (_src->at(i) == _dst->at(i)) {
      return;
    }
    _status->at(i) = Status::BeingMoved;
    for (int j = 0; j < _n; ++j) {
      if (_src->at(j) != _dst->at(i)) {
        continue;
      }
      switch (_status->at(j)) {
        case Status::ToMove:
          move_one(j);
          break;
        case Status::BeingMoved: {
          // j is an ancestor in the recursion, so we have closed a
          // cycle. Spill its source to scratch and read from there.
          auto scratch = _tmp(_src->at(j));
          assert(scratch != _src->at(j), "don't do that");
          _move(scratch, _src->at(j));
          _src->at(j) = scratch;
          break;
        }
        case Status::Moved:
          break;
      }
    }
    _move(_dst->at(i), _src->at(i));
    _status->at(i) = Status::Moved;
  }

  void doIt() {
    for (int i = 0; i < _n; ++i) {
      if (_status->at(i) == Status::ToMove) {
        move_one(i);
      }
    }
  }
};

template<typename Reg, typename TempFn, typename MoveFn>
void parallel_move(GrowableArrayView<Reg> *src,
                   GrowableArrayView<Reg> *dst,
                   const TempFn tmp,
                   const MoveFn move) {
  ParallelMover(src, dst, tmp, move).doIt();
}

template<typename Reg, size_t N, typename TempFn, typename MoveFn>
void parallel_move(const Reg (&src)[N],
                   const Reg (&dst)[N],
                   const TempFn tmp,
                   const MoveFn move) {
  Reg src_copy[N], dst_copy[N];
  memcpy(src_copy, const_cast<Reg*>(src), sizeof src);
  memcpy(dst_copy, const_cast<Reg*>(dst), sizeof dst);
  GrowableArrayFromArray src_array(src_copy, N);
  GrowableArrayFromArray dst_array(dst_copy, N);
  parallel_move(&src_array, &dst_array, tmp, move);
}

#endif // SHARE_UTILITIES_PMOVE_HPP
